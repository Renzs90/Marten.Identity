# Marten.Identity
MartenDB provider for ASP.NET Core Identity framework.
Heavily inspired by [Cosmos.Identity](https://github.com/loresoft/Cosmos.Identity).

## Usage
appsettings.json configuration

```json
{
  "ConnectionStrings": {
    "Marten": "HOST=127.0.0.1;PORT=5432;DATABASE='MartenIdentityApp';USER ID='martenidentityuser';PASSWORD='martenidentitypassword';TIMEOUT=15;POOLING=True;MINPOOLSIZE=1;MAXPOOLSIZE=100;COMMANDTIMEOUT=20;"
  }
}
```

docker-compose file

```yml
version: '3.4'

services:
  postgres_marten_db:
    image: postgres:latest
    environment:
      - POSTGRES_USER=martenidentityuser
      - POSTGRES_PASSWORD=martenidentitypassword
      - POSTGRES_DB=MartenIdentityApp
    ports:
      - "5432:5432"
    restart: always
    volumes:
      - psg-marten-data:/var/lib/postgres/data

  postgres_dashboard:
    image: dpage/pgadmin4
    environment:
      - PGADMIN_DEFAULT_EMAIL=admin@local.me
      - PGADMIN_DEFAULT_PASSWORD=admin
    ports:
      - "7123:80"
    restart: always
    volumes: 
      - pgadmin:/root/.pgadmin

volumes:
  psg-marten-data:
  pgadmin:
```

Program.cs

```c#
using Marten;
using Marten.Identity;
using Marten.Schema;
using Marten.Schema.Identity;
using Microsoft.AspNetCore.Identity;
using Weasel.Core;
using IdentityRole = Marten.Identity.IdentityRole;
using IdentityUser = Marten.Identity.IdentityUser;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMarten(options =>
{
    // Establish the connection string to your Marten database
    options.Connection(builder.Configuration.GetConnectionString("Marten"));

    // If we're running in development mode, let Marten just take care
    // of all necessary schema building and patching behind the scenes
    if (builder.Environment.IsDevelopment())
    {
        options.AutoCreateSchemaObjects = AutoCreate.All;
    }

    options.Schema.For<IdentityUser>()
        .IdStrategy(new CombGuidIdGeneration())
        .UniqueIndex(UniqueIndexType.Computed, x => x.NormalizedUserName, x => x.NormalizedEmail);

    options.Schema.For<IdentityRole>()
        .IdStrategy(new CombGuidIdGeneration())
        .UniqueIndex(UniqueIndexType.Computed, x => x.NormalizedName);

});

builder.Services
    .AddIdentity<IdentityUser, IdentityRole>()
    .AddMartenStores()
    .AddDefaultUI()
    .AddDefaultTokenProviders();

// and services and configuration we don't care about right now...
```