package repos

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/gitlabroles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type selectiveSecretClient struct {
	forge.Client
	fail map[string]error
}

func (c *selectiveSecretClient) CreateRepoSecret(ctx context.Context, owner, repo, name, value string) error {
	if err, ok := c.fail[name]; ok {
		return err
	}
	return c.Client.CreateRepoSecret(ctx, owner, repo, name, value)
}

func seededRoleClient(t *testing.T, roles ...gitlabroles.Role) *forge.FakeClient {
	t.Helper()
	fc := provisionClient(t)
	for _, role := range roles {
		var secret string
		switch role {
		case gitlabroles.RolePoller:
			secret = forge.SecretGitLabPollerToken
		case gitlabroles.RoleAnalyst:
			secret = forge.SecretGitLabAnalystToken
		case gitlabroles.RoleCoder:
			secret = forge.SecretGitLabCoderToken
		default:
			secret = gitlabroles.CustomSecretName(role)
		}
		require.NoError(t, fc.CreateRepoSecret(context.Background(), "group", "project", secret, "oldvalueXXXX"))
	}
	return fc
}

func TestRotateGitLabRoleCredentials_EachBuiltinIndependently(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	for _, role := range gitlabroles.BuiltinRoles() {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			fc := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst, gitlabroles.RoleCoder)
			tokens := &fakeTokens{}
			var tokenName string
			switch role {
			case gitlabroles.RolePoller:
				tokenName = gitlabroles.PollerTokenName
			case gitlabroles.RoleAnalyst:
				tokenName = gitlabroles.AnalystTokenName
			case gitlabroles.RoleCoder:
				tokenName = gitlabroles.CoderTokenName
			}
			tokens.seed(ProjectAccessToken{Name: tokenName, Active: true, ExpiresAt: "2026-10-01"})

			result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
				Owner:    "group",
				Repo:     "project",
				Client:   fc,
				Tokens:   tokens,
				Registry: gitlabroles.BuiltinRegistry(),
				Mode:     gitlabroles.ModeMigrating,
				Roles:    []gitlabroles.Role{role},
				Now:      now,
			})
			require.NoError(t, err)
			assert.True(t, result.SharedPreserved)
			assert.Equal(t, []gitlabroles.Role{role}, result.Rotated)
			assert.Contains(t, result.Overlapping, role)
			assert.Empty(t, result.Failed)
			assert.Len(t, tokens.created, 1)
			assert.Empty(t, tokens.revoked, "previous PAT stays valid for in-flight jobs")
			assert.True(t, fc.Secrets["group/project/"+forge.SecretForgeToken])
			for _, d := range result.Diagnostics {
				assertNoLeak(t, d)
			}
		})
	}
}

func TestRotateGitLabRoleCredentials_CustomOwnAndReuse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	reg, err := gitlabroles.ParseRegistry(`{
		"roles": [
			{"name":"scanner","credential":"own","capabilities":["read_issues"],"agents":["scanner"]},
			{"name":"deployer","credential":"reuse","reuse":"coder","capabilities":["write_repository"],"agents":["deploy"]}
		]
	}`)
	require.NoError(t, err)
	fc := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst, gitlabroles.RoleCoder, gitlabroles.Role("scanner"))
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{ID: 1, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{ID: 2, Name: gitlabroles.AnalystTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{ID: 3, Name: gitlabroles.CoderTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.CustomTokenName("scanner"), Active: true, ExpiresAt: "2026-10-01"})
	// poller/analyst/coder are already healthy and distributed (as a real
	// prior rotation or initial provisioning would have recorded): give
	// them rotation-state proof so they are correctly treated as not due,
	// rather than as unproven live tokens that must be replaced.
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation, `{"roles":{
		"poller":{"phase":"idle","incoming_id":1,"distributed_at":"2026-06-01T00:00:00Z"},
		"analyst":{"phase":"idle","incoming_id":2,"distributed_at":"2026-06-01T00:00:00Z"},
		"coder":{"phase":"idle","incoming_id":3,"distributed_at":"2026-06-01T00:00:00Z"}
	}}`, true))

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: reg,
		Mode:     gitlabroles.ModeEnforced,
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.Role("scanner")}, result.Rotated)
	assert.Contains(t, result.Reused, gitlabroles.Role("deployer"))
	assert.NotContains(t, tokens.createdNames(), gitlabroles.CoderTokenName)
	assert.Contains(t, tokens.createdNames(), gitlabroles.CustomTokenName("scanner"))
	assert.Empty(t, tokens.revoked)
}

func TestRotateGitLabRoleCredentials_ConcurrentSerializedAndIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst, gitlabroles.RoleCoder)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.AnalystTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.CoderTokenName, Active: true, ExpiresAt: "2027-09-21"})

	cfg := RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Force:    true,
		Now:      now,
	}

	var wg sync.WaitGroup
	results := make([]RoleRotateResult, 2)
	errs := make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = RotateGitLabRoleCredentials(context.Background(), cfg)
		}(i)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.Len(t, tokens.created, 1, "concurrent force-rotate must mint exactly one replacement")
	rotated := 0
	for _, r := range results {
		assert.True(t, r.SharedPreserved)
		if len(r.Rotated) > 0 {
			rotated++
		}
		for _, d := range r.Diagnostics {
			assertNoLeak(t, d)
		}
	}
	assert.Equal(t, 1, rotated)
}

func TestRotateGitLabRoleCredentials_FailedDistributionRollsBack(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	inner := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst, gitlabroles.RoleCoder)
	fc := &selectiveSecretClient{
		Client: inner,
		fail:   map[string]error{forge.SecretGitLabPollerToken: fmt.Errorf("forbidden")},
	}
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.RolledBack)
	require.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed[0].Reason, "previous credential left in place")
	require.Len(t, tokens.created, 1)
	assert.Equal(t, []int{tokens.created[0].ID}, tokens.revoked)
	assert.True(t, inner.Secrets["group/project/"+forge.SecretGitLabPollerToken])
	assert.True(t, inner.Secrets["group/project/"+forge.SecretForgeToken])
	// The last successful write for the poller secret is still the seed.
	var last string
	for _, rec := range inner.CreatedSecrets {
		if rec.Name == forge.SecretGitLabPollerToken {
			last = rec.Value
		}
	}
	assert.Equal(t, "oldvalueXXXX", last)
	for _, d := range result.Diagnostics {
		assertNoLeak(t, d)
	}
	for _, f := range result.Failed {
		assertNoLeak(t, f.Reason)
	}
}

func TestRotateGitLabRoleCredentials_FailedCreateLeavesPrevious(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{failCreate: map[string]error{
		gitlabroles.PollerTokenName: fmt.Errorf("gitlab down"),
	}}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeEnforced,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	require.Len(t, result.Failed, 1)
	assert.Empty(t, result.Rotated)
	assert.Empty(t, tokens.created)
	assert.Empty(t, tokens.revoked)
	assert.True(t, fc.Secrets["group/project/"+forge.SecretGitLabPollerToken])
}

func TestRotateGitLabRoleCredentials_InFlightKeepsPreviousPAT(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Overlapping, gitlabroles.RolePoller)
	assert.Empty(t, tokens.revoked)
	assert.Contains(t, strings.Join(result.Diagnostics, "\n"), "in-flight")
	active := 0
	for _, tok := range tokens.listed {
		if tok.Name == gitlabroles.PollerTokenName && tok.Active {
			active++
		}
	}
	assert.Equal(t, 2, active)
}

func TestRotateGitLabRoleCredentials_GraceCleanupRevokesOutgoing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	_, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	require.Len(t, tokens.created, 1)
	assert.Empty(t, tokens.revoked)

	later := now.Add(25 * time.Hour)
	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      later,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Cleaned, gitlabroles.RolePoller)
	assert.Empty(t, result.Rotated, "new token is not due")
	assert.Equal(t, []int{1}, tokens.revoked)
}

func TestRotateGitLabRoleCredentials_DisabledSkipsWithoutForce(t *testing.T) {
	t.Parallel()
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeDisabled,
		Now:      time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	assert.Empty(t, result.Rotated)
	assert.Empty(t, tokens.created)
	assert.Contains(t, strings.Join(result.Diagnostics, "\n"), "skip rotation")
}

func TestRotateGitLabRoleCredentials_DryRunDoesNotWrite(t *testing.T) {
	t.Parallel()
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	before := len(fc.CreatedSecrets)

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		DryRun:   true,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	assert.Empty(t, tokens.created)
	assert.Equal(t, before, len(fc.CreatedSecrets))
	_, hasState := fc.VariableValues["group/project/"+forge.VarGitLabRoleRotation]
	assert.False(t, hasState)
}

func TestRotateGitLabRoleCredentials_ProvidedReplacement(t *testing.T) {
	t.Parallel()
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Force:    true,
		Now:      time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		ProvidedTokens: map[gitlabroles.Role]string{
			gitlabroles.RolePoller: "enrolledXXXX",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	assert.Empty(t, tokens.created)
	var last string
	for _, rec := range fc.CreatedSecrets {
		if rec.Name == forge.SecretGitLabPollerToken {
			last = rec.Value
		}
	}
	assert.Equal(t, "enrolledXXXX", last)
}

func TestRotateGitLabRoleCredentials_ProvidedReplacementDoesNotScheduleSelfForRevocation(t *testing.T) {
	t.Parallel()
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	// The administrator enrolls a replacement PAT that GitLab already
	// lists under the role's token name (the documented free-tier
	// workflow: create it via the UI since the API requires GitLab
	// Premium/Ultimate, then pass its value here). Rotation has no way
	// to learn this listed token's own ID from the provided value alone.
	tokens.seed(ProjectAccessToken{ID: 9, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Force:    true,
		Now:      time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		ProvidedTokens: map[gitlabroles.Role]string{
			gitlabroles.RolePoller: "enrolledXXXX",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	assert.Empty(t, result.Overlapping, "no same-named PAT is scheduled for grace revocation, so there is no tracked overlap")

	raw := fc.VariableValues["group/project/"+forge.VarGitLabRoleRotation]
	assert.NotContains(t, raw, `"outgoing_ids":[9]`,
		"the just-enrolled replacement must never be recorded for grace revocation when its own ID cannot be resolved")
	assert.Contains(t, raw, `"phase":"idle"`)
}

func TestRotateGitLabRoleCredentials_ProvidedUnmaskableAndStoreFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

	t.Run("unmaskable", func(t *testing.T) {
		fc := seededRoleClient(t, gitlabroles.RolePoller)
		result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
			Owner: "group", Repo: "project", Client: fc, Tokens: &fakeTokens{},
			Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
			Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Force: true, Now: now,
			ProvidedTokens: map[gitlabroles.Role]string{gitlabroles.RolePoller: "short"},
		})
		require.NoError(t, err)
		require.Len(t, result.Failed, 1)
		assert.Contains(t, result.Failed[0].Reason, "cannot be masked")
	})

	t.Run("store failure", func(t *testing.T) {
		inner := seededRoleClient(t, gitlabroles.RolePoller)
		fc := &selectiveSecretClient{Client: inner, fail: map[string]error{forge.SecretGitLabPollerToken: fmt.Errorf("nope")}}
		result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
			Owner: "group", Repo: "project", Client: fc, Tokens: &fakeTokens{},
			Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
			Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Force: true, Now: now,
			ProvidedTokens: map[gitlabroles.Role]string{gitlabroles.RolePoller: "enrolledXXXX"},
		})
		require.NoError(t, err)
		require.Len(t, result.Failed, 1)
		assert.Contains(t, result.Failed[0].Reason, "previous credential left in place")
	})

	t.Run("dry-run", func(t *testing.T) {
		fc := seededRoleClient(t, gitlabroles.RolePoller)
		before := len(fc.CreatedSecrets)
		result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
			Owner: "group", Repo: "project", Client: fc, Tokens: &fakeTokens{},
			Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
			Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Force: true, Now: now, DryRun: true,
			ProvidedTokens: map[gitlabroles.Role]string{gitlabroles.RolePoller: "enrolledXXXX"},
		})
		require.NoError(t, err)
		assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
		assert.Equal(t, before, len(fc.CreatedSecrets))
	})
}

// siblingInjector simulates a concurrent process writing a sibling
// role's rotation state into the shared FULLSEND_GITLAB_ROLE_ROTATION
// document immediately after this process's first write (its lock
// claim). Since the forge variable API has no compare-and-swap, this is
// the realistic trigger for the race in
// TestRotateGitLabRoleCredentials_ConcurrentSiblingRoleSurvives: two
// concurrent `repos install`/`repos rotate` processes rotating
// different roles against the same document.
type siblingInjector struct {
	*forge.FakeClient
	injected bool
}

func (c *siblingInjector) UpdateCIVariable(ctx context.Context, owner, repo, name, value string, protected bool) error {
	if err := c.FakeClient.UpdateCIVariable(ctx, owner, repo, name, value, protected); err != nil {
		return err
	}
	if name != forge.VarGitLabRoleRotation || c.injected {
		return nil
	}
	c.injected = true
	file, _, err := loadRotationState(ctx, c.FakeClient, owner, repo)
	if err != nil {
		return err
	}
	file.Roles[string(gitlabroles.RoleAnalyst)] = rotationRoleState{
		Phase: rotationPhaseIdle, IncomingID: 42, DistributedAt: "2026-09-20T00:00:00Z",
	}
	return writeRotationState(ctx, c.FakeClient, owner, repo, file)
}

func TestRotateGitLabRoleCredentials_ConcurrentSiblingRoleSurvives(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	inner := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst)
	fc := &siblingInjector{FakeClient: inner}
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	require.True(t, fc.injected, "the sibling write must have landed for this test to be meaningful")

	final, _, err := loadRotationState(context.Background(), inner, "group", "project")
	require.NoError(t, err)
	analyst, ok := final.Roles[string(gitlabroles.RoleAnalyst)]
	require.True(t, ok, "a sibling role's concurrent update must survive this role's subsequent writes")
	assert.Equal(t, 42, analyst.IncomingID)
	assert.Equal(t, "2026-09-20T00:00:00Z", analyst.DistributedAt)
}

// siblingReadInjector simulates a concurrent process writing a sibling
// role's rotation state into the shared FULLSEND_GITLAB_ROLE_ROTATION
// document immediately after this process's first read of it
// (loadRotationState, before the lock-claim write persists anything).
// This is the narrower window TestRotateGitLabRoleCredentials_
// ConcurrentSiblingRoleSurvives does not cover: that test only injects
// after this process's first write, whereas the lock-claim write itself
// used to persist the snapshot loaded before the injected sibling write
// landed, reverting it.
type siblingReadInjector struct {
	*forge.FakeClient
	injected bool
}

func (c *siblingReadInjector) GetRepoVariable(ctx context.Context, owner, repo, name string) (string, bool, error) {
	raw, exists, err := c.FakeClient.GetRepoVariable(ctx, owner, repo, name)
	if name != forge.VarGitLabRoleRotation || c.injected {
		return raw, exists, err
	}
	c.injected = true
	file, _, loadErr := loadRotationState(ctx, c.FakeClient, owner, repo)
	if loadErr == nil {
		file.Roles[string(gitlabroles.RoleAnalyst)] = rotationRoleState{
			Phase: rotationPhaseIdle, IncomingID: 42, DistributedAt: "2026-09-20T00:00:00Z",
		}
		_ = writeRotationState(ctx, c.FakeClient, owner, repo, file)
	}
	return raw, exists, err
}

func TestRotateGitLabRoleCredentials_ConcurrentSiblingRoleSurvivesLockClaim(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	inner := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst)
	fc := &siblingReadInjector{FakeClient: inner}
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	require.True(t, fc.injected, "the sibling write must have landed for this test to be meaningful")

	final, _, err := loadRotationState(context.Background(), inner, "group", "project")
	require.NoError(t, err)
	analyst, ok := final.Roles[string(gitlabroles.RoleAnalyst)]
	require.True(t, ok, "a sibling role's concurrent update landing before the lock-claim write must survive")
	assert.Equal(t, 42, analyst.IncomingID)
	assert.Equal(t, "2026-09-20T00:00:00Z", analyst.DistributedAt)
}

func TestRotateGitLabRoleCredentials_InProgressLock(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation,
		`{"roles":{"poller":{"phase":"overlapping","holder":"other","lock_until":"2026-09-21T13:00:00Z","incoming_id":9}}}`, true))

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner: "group", Repo: "project", Client: fc, Tokens: tokens,
		Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
		Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Now: now, Holder: "self",
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.InProgress)
	assert.Empty(t, tokens.created)
}

func TestRotateGitLabRoleCredentials_InvalidStateAndEmptyCreate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation,
		`{"roles":{"poller":{"unknown":true}}}`, true))
	tokens := &fakeTokens{emptyValue: map[string]bool{gitlabroles.PollerTokenName: true}}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner: "group", Repo: "project", Client: fc, Tokens: tokens,
		Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
		Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Now: now,
	})
	require.NoError(t, err)
	assert.Contains(t, strings.Join(result.Diagnostics, "\n"), "invalid or unavailable")
	require.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed[0].Reason, "reading rotation state failed")
	assert.Empty(t, tokens.created)
}

func TestRotateGitLabRoleCredentials_EmptyCreateValue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{emptyValue: map[string]bool{gitlabroles.PollerTokenName: true}}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner: "group", Repo: "project", Client: fc, Tokens: tokens,
		Registry: gitlabroles.BuiltinRegistry(), Mode: gitlabroles.ModeMigrating,
		Roles: []gitlabroles.Role{gitlabroles.RolePoller}, Now: now,
	})
	require.NoError(t, err)
	require.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed[0].Reason, "returned no value")
}

func TestRotateGitLabRoleCredentials_ForceWithoutTokenClient(t *testing.T) {
	t.Parallel()
	_, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner: "group", Repo: "project", Client: provisionClient(t),
		Mode: gitlabroles.ModeMigrating, Force: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token client")
}

func TestSecretLeakRotateAndWriteState(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, secretLeakRotate(RoleRotateResult{Diagnostics: []string{"glpat-LEAK"}}))
	assert.NotEmpty(t, secretLeakRotate(RoleRotateResult{Failed: []RoleProvisionFailure{{Reason: "gldt-x"}}}))
	assert.Empty(t, secretLeakRotate(RoleRotateResult{Diagnostics: []string{"ok"}}))

	fc := provisionClient(t)
	require.NoError(t, writeRotationState(context.Background(), fc, "group", "project", rotationStateFile{}))
	raw := fc.VariableValues["group/project/"+forge.VarGitLabRoleRotation]
	assert.Contains(t, raw, `"roles"`)
}

func TestRotateGitLabRoleCredentials_NilClientAndInvalidMode(t *testing.T) {
	t.Parallel()
	_, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{})
	require.Error(t, err)
	_, err = RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Client: provisionClient(t),
		Mode:   gitlabroles.Mode("nope"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, gitlabroles.ErrInvalidMode)
}

func TestRotateGitLabRoleCredentials_DoesNotTouchSharedToken(t *testing.T) {
	t.Parallel()
	fc := seededRoleClient(t, gitlabroles.RolePoller, gitlabroles.RoleAnalyst, gitlabroles.RoleCoder)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.SharedTokenName, Active: true, ExpiresAt: "2026-10-01"})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeEnforced,
		Force:    true,
		Now:      time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	assert.True(t, result.SharedPreserved)
	for _, name := range tokens.createdNames() {
		assert.NotEqual(t, gitlabroles.SharedTokenName, name)
	}
	assert.NotContains(t, tokens.revoked, 2, "shared fullsend-bot PAT must not be revoked")
}

func TestEnrichGitLabRoleStatusExpiredIsDriftWhenEnforced(t *testing.T) {
	t.Parallel()
	fc := provisionClient(t)
	fc.VariableValues["group/project/"+forge.VarGitLabRoleMigration] = "enforced"
	fc.VariablesExist["group/project/"+forge.VarGitLabRoleMigration] = true
	require.NoError(t, fc.CreateRepoSecret(context.Background(), "group", "project", forge.SecretGitLabPollerToken, "oldvalueXXXX"))
	require.NoError(t, fc.CreateRepoSecret(context.Background(), "group", "project", forge.SecretGitLabAnalystToken, "oldvalueXXXX"))
	require.NoError(t, fc.CreateRepoSecret(context.Background(), "group", "project", forge.SecretGitLabCoderToken, "oldvalueXXXX"))

	status := &RepoStatus{}
	appendGitLabRoleStatus(context.Background(), fc, "group", "project", status)
	EnrichGitLabRoleStatus(context.Background(), fc, "group", "project", []ProjectAccessToken{
		{ID: 1, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-01-01"},
		{ID: 2, Name: gitlabroles.AnalystTokenName, Active: true, ExpiresAt: "2027-09-21"},
		{ID: 3, Name: gitlabroles.CoderTokenName, Active: false, ExpiresAt: "2027-09-21"},
	}, time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC), status)
	EnrichGitLabRoleStatus(context.Background(), nil, "group", "project", nil, time.Time{}, nil)

	joined := strings.Join(status.GitLabRoleDiagnostics, "\n")
	assert.Contains(t, joined, "expired")
	assert.Contains(t, joined, "revoked")
	var actuals []string
	for _, d := range status.Drifts {
		actuals = append(actuals, d.Field+"="+d.Actual)
		assertNoLeak(t, d.Field)
		assertNoLeak(t, d.Actual)
	}
	assert.Contains(t, strings.Join(actuals, ","), "gitlab-role:poller=expired")
	assert.Contains(t, strings.Join(actuals, ","), "gitlab-role:coder=revoked")
}

func TestRotateGitLabRoleCredentials_RecoveryAfterPartialDistribution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{ID: 7, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	tokens.seed(ProjectAccessToken{ID: 8, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation,
		`{"roles":{"poller":{"phase":"distributing","incoming_id":8,"outgoing_ids":[7]}}}`, true))

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
		Force:    true,
	})
	require.NoError(t, err)
	assert.NotContains(t, tokens.revoked, 8, "incoming PAT may already be the live distributed credential")
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated)
	assert.NotContains(t, tokens.revoked, 7, "last known-good PAT stays until grace cleanup")
}

func TestRotateGitLabRoleCredentials_RecoveryAfterPartialDistributionWithoutForce(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	tokens.seed(ProjectAccessToken{ID: 7, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	// The incoming token has a long-lived expiry matching GitLabPATExpiresAt(now),
	// which is exactly what makes an unproven "already fresh" skip look plausible.
	tokens.seed(ProjectAccessToken{ID: 8, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation,
		`{"roles":{"poller":{"phase":"distributing","incoming_id":8,"outgoing_ids":[7]}}}`, true))

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.NotContains(t, result.Skipped, gitlabroles.RolePoller,
		"an incomplete distributing phase must reach recovery even on the default auto-rotate (non-Force) path")
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated,
		"recovery must actually mint and distribute a replacement, not merely avoid Skipped")
	require.Len(t, tokens.created, 1, "recovery must mint exactly one replacement token")
	assert.NotContains(t, tokens.revoked, 8, "incoming PAT may already be the live distributed credential")
	assert.NotContains(t, tokens.revoked, 7, "last known-good PAT stays until grace cleanup")
}

func TestRotateGitLabRoleCredentials_OrphanBeforeFirstStateWriteIsNotTrustedAsDue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	// ID 7 is the last state-recorded distribution (legitimate, from a
	// previous run) and is now approaching expiry. ID 8 models an orphan
	// minted by a crashed retry that succeeded in creating a replacement
	// but crashed before any rotation-state write recorded it.
	tokens.seed(ProjectAccessToken{ID: 7, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2026-10-01"})
	tokens.seed(ProjectAccessToken{ID: 8, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})
	require.NoError(t, fc.UpdateCIVariable(context.Background(), "group", "project", forge.VarGitLabRoleRotation,
		`{"roles":{"poller":{"phase":"idle","incoming_id":7,"outgoing_ids":[],"distributed_at":"2026-06-01T00:00:00Z"}}}`, true))

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated,
		"an orphan token from a crash before the first state write must not be trusted as proof rotation already succeeded")
	require.Len(t, tokens.created, 1)
	raw := fc.VariableValues["group/project/"+forge.VarGitLabRoleRotation]
	assert.Contains(t, raw, fmt.Sprintf(`"incoming_id":%d`, tokens.created[0].ID))
	assert.Contains(t, raw, "\"outgoing_ids\":[7,8]", "both the old distributed token and the orphan must be tracked for grace cleanup")
}

// TestRotateGitLabRoleCredentials_SingleUnprovenOrphanIsNotTrustedAsDue
// covers the narrower crash window than
// TestRotateGitLabRoleCredentials_OrphanBeforeFirstStateWriteIsNotTrustedAsDue:
// here only the crash-created orphan token exists (no second live PAT,
// and no prior rotation state at all), which used to make the old
// needsProof gate stay false (no overlap, no distributing/failed phase)
// and let the single fresh-looking PAT slip through as "already
// rotated" / "not due" without any proof this process (or provisioning)
// ever distributed it.
func TestRotateGitLabRoleCredentials_SingleUnprovenOrphanIsNotTrustedAsDue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	fc := seededRoleClient(t, gitlabroles.RolePoller)
	tokens := &fakeTokens{}
	// A single active same-named PAT, freshly minted "today" as if
	// CreateProjectAccessToken succeeded moments before the process
	// crashed and never wrote phase=distributing. No rotation state
	// exists at all for this role (first run for this document).
	tokens.seed(ProjectAccessToken{ID: 9, Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: GitLabPATExpiresAt(now)})

	result, err := RotateGitLabRoleCredentials(context.Background(), RoleRotateConfig{
		Owner:    "group",
		Repo:     "project",
		Client:   fc,
		Tokens:   tokens,
		Registry: gitlabroles.BuiltinRegistry(),
		Mode:     gitlabroles.ModeMigrating,
		Roles:    []gitlabroles.Role{gitlabroles.RolePoller},
		Now:      now,
	})
	require.NoError(t, err)
	assert.Equal(t, []gitlabroles.Role{gitlabroles.RolePoller}, result.Rotated,
		"a single unproven same-named PAT must not be trusted as evidence rotation already succeeded")
	assert.NotContains(t, result.Skipped, gitlabroles.RolePoller)
	require.Len(t, tokens.created, 1)
	assert.NotContains(t, tokens.revoked, 9, "the orphan stays valid for in-flight jobs until grace cleanup")
	raw := fc.VariableValues["group/project/"+forge.VarGitLabRoleRotation]
	assert.Contains(t, raw, fmt.Sprintf(`"incoming_id":%d`, tokens.created[0].ID))
	assert.Contains(t, raw, "\"outgoing_ids\":[9]", "the orphan must be tracked for grace cleanup")
}
