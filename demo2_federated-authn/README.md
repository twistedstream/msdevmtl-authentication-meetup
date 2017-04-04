# Demo 2: Federated authentication with ASP.NET Core

The purpose of this demo is to modify a website that only uses local forms-based authentication, so that it can also accept federated users from an external IDP. We start with a standard ASP.NET Core website (with identity enabled for indivual authentication) and then enable authentication with Google. 

You can see the progression in the GitHub commits, but to reproduce this yourself, follow these steps.

First, to set up the standard website:

1. Create the initial solution and project from a .NET template:

   ```bash
   dotnet new sln -n FederatedAuth
   dotnet new mvc --auth Individual -n FederatedAuth.Website
   dotnet sln FederatedAuth.sln add FederatedAuth.Website/FederatedAuth.Website.csproj
   ```

1. Perform automatic DB migration on startup if running in dev mode (see [this commit](c103d9c1f7c6cc978908dfad7bfc4a879fba4d6b)). This prevents you from having to run the `dotnet ef database update` command before you first run the sample.

Then to enable federation with Google, you can follow the guidance from [this Microsoft docs page](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins). But the specific steps are:

1. Create your Google app and obtain the Client ID and Client Secret
1. Store them using the [Secret Manager](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets):

   ```
   dotnet user-secrets set Authentication:Google:ClientID GOOGLE_CLIENT_ID

   dotnet user-secrets set Authentication:Google:ClientSecret GOOGLE_CLIENT_SECRET
   ```

1. Add this code to `Configure` method of `Startup.cs` _after_ the call to `UseIdentity`:

   ```c#
   app.UseGoogleAuthentication(new GoogleOptions()
   {
       ClientId = Configuration["Authentication:Google:ClientId"],
       ClientSecret = Configuration["Authentication:Google:ClientSecret"]
   });
   ```
   
When you run the website now and go to the **Log in** page, you should now see a **Google** button on the right side under the **Use another service to log in** section.
