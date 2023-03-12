using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Marten.Identity;

public static class IdentityBuilderExtensions
{
    public static IdentityBuilder AddMartenStores(this IdentityBuilder builder)
    {
        if (builder == null)
            throw new ArgumentNullException(nameof(builder));

        var userType = builder.UserType;
        var roleType = builder.RoleType;

        if (userType is null)
            throw new InvalidOperationException(
                $"Must provide an identity user of type {typeof(IdentityUser).FullName} or one that extends this type.");
        if (!typeof(IdentityUser).IsAssignableFrom(userType))
            throw new InvalidOperationException($"{userType.Name} must extend {typeof(IdentityUser).FullName}.");

        if (roleType is null)
            roleType = typeof(IdentityRole);
        else if (!typeof(IdentityRole).IsAssignableFrom(roleType))
            throw new InvalidOperationException($"{roleType.Name} must extend {typeof(IdentityRole).FullName}.");

        var userStoreType = typeof(UserStore<>).MakeGenericType(userType);
        var roleStoreType = typeof(RoleStore<>).MakeGenericType(roleType);

        builder.Services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserLoginStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserClaimStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserPasswordStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserSecurityStampStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserEmailStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserLockoutStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserPhoneNumberStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IQueryableUserStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserTwoFactorStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserAuthenticationTokenStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserAuthenticatorKeyStore<>).MakeGenericType(userType), userStoreType);
        builder.Services.TryAddScoped(typeof(IUserTwoFactorRecoveryCodeStore<>).MakeGenericType(userType),
            userStoreType);
        builder.Services.TryAddScoped(typeof(IUserRoleStore<>).MakeGenericType(userType), userStoreType);

        builder.Services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
        builder.Services.TryAddScoped(typeof(IRoleClaimStore<>).MakeGenericType(roleType), roleStoreType);

        return builder;
    }
}