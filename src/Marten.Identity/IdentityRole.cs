namespace Marten.Identity;

public class IdentityRole
{
    public Guid Id { get; set; }

    public string Name { get; set; }

    public string NormalizedName { get; set; }

    public IList<IdentityClaim> Claims { get; set; }
}