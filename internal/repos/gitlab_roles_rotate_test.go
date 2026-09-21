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
	tokens.seed(ProjectAccessToken{Name: gitlabroles.PollerTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.AnalystTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.CoderTokenName, Active: true, ExpiresAt: "2027-09-21"})
	tokens.seed(ProjectAccessToken{Name: gitlabroles.CustomTokenName("scanner"), Active: true, ExpiresAt: "2026-10-01"})

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
