namespace Marten.Identity;

public class IdentityToken
{
    public string LoginProvider { get; set; }

    public string Name { get; set; }

    public string Value { get; set; }
}