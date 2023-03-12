using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Marten.Identity;

internal class RoleStore<TRole> :
    IQueryableRoleStore<TRole>,
    IRoleClaimStore<TRole>
    where TRole : IdentityRole
{
    private readonly IDocumentSession _session;

    public RoleStore(IDocumentSession session)
    {
        _session = session;
    }

    public void Dispose()
    {
        _session.Dispose();
    }

    public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
    {
        try
        {
            _session.Store(role);

            await _session.SaveChangesAsync(cancellationToken);

            return IdentityResult.Success;
        }
        catch (Exception ex)
        {    
            return IdentityResult.Failed(new IdentityError { Description = ex.Message });
        }
    }

    public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
    {
        try
        {
            _session.Update(role);
        
            await _session.SaveChangesAsync(cancellationToken);

            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            return IdentityResult.Failed(new IdentityError { Description = ex.Message });
        }
    }

    public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
    {
        try
        {
            _session.Delete(role);

            await _session.SaveChangesAsync(cancellationToken);

            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            return IdentityResult.Failed(new IdentityError { Description = ex.Message });
        }
    }

    public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
    {
        ValidateParameters(role, cancellationToken);

        return Task.FromResult(role.Id.ToString());
    }

    public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
    {
        ValidateParameters(role, cancellationToken);

        return Task.FromResult(role.Name);
    }

    public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
    {
        if (roleName == null)
            throw new ArgumentNullException(nameof(roleName));

        ValidateParameters(role, cancellationToken);

        role.Name = roleName;

        return Task.CompletedTask;
    }

    public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
    {
        ValidateParameters(role, cancellationToken);

        return Task.FromResult(role.NormalizedName);
    }

    public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
    {
        if (normalizedName == null)
            throw new ArgumentNullException(nameof(normalizedName));

        ValidateParameters(role, cancellationToken);

        role.NormalizedName = normalizedName;
        return Task.CompletedTask;
    }

    public Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
    {
        return _session.Query<TRole>().FirstAsync(x => x.Id == Guid.Parse(roleId), cancellationToken);
    }

    public Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        return _session.Query<TRole>()
            .FirstAsync(x => x.NormalizedName == normalizedRoleName, cancellationToken);
    }

    public IQueryable<TRole> Roles => _session.Query<TRole>();

    public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = new())
    {
        ValidateParameters(role, cancellationToken);

        var claims = role.Claims
            .Select(c => new Claim(c.Type, c.Value))
            .ToList();

        return Task.FromResult<IList<Claim>>(claims);
    }

    public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new())
    {
        ValidateParameters(role, cancellationToken);

        if (claim == null)
            throw new ArgumentNullException(nameof(claim));

        var roleClaim = new IdentityClaim
        {
            Type = claim.Type,
            Value = claim.Value
        };
        role.Claims.Add(roleClaim);

        return Task.CompletedTask;
    }

    public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new())
    {
        ValidateParameters(role, cancellationToken);

        if (claim == null)
            throw new ArgumentNullException(nameof(claim));

        var matched = role.Claims
            .Where(u => u.Value == claim.Value && u.Type == claim.Type)
            .ToList();

        foreach (var m in matched)
            role.Claims.Remove(m);

        return Task.CompletedTask;
    }

    private static void ValidateParameters(IdentityRole role, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (role == null)
            throw new ArgumentNullException(nameof(role));
    }
}