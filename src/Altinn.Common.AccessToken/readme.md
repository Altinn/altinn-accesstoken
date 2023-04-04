## AccessToken Library

### Usage

#### AccessTokenHandler

AccessTokenHandler depends on requirement _AccessTokenRequirement_.
To register the handler in your application add the code below in your service registration in Program.cs

```cs
services.AddSingleton<IAuthorizationHandler, AccessTokenHandler>();
```

#### AccessTokenHandler{T}

There is support for a generic accesstoken handler to support a requirement T.


To use this create a new requirement as shown below.

```cs
 public class CustomRequirement : IAuthorizationRequirement
    {
        public CustomRequirement()
        {
        }
    }
```

In Program.cs register a new policy in your `services.AddAuthorization( options => {})` method
as shown below.

```cs
options.AddPolicy("CustomRequirement", policy =>
{
  policy.Requirements.Add(new CustomRequirement());
});
```

FInal step is to register the handler in Program.cs

```cs
services.AddSingleton<IAuthorizationHandler, AccessTokenHandler<CustomRequirement>>();
```

#### Dependencies

Implementations of `IHttpContextAccessor` and `ISigningKeysResolver` must be available through DI when using access token handler.

Add the following to your servie registration in Program.cs

```cs
services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
services.AddSingleton<ISigningKeysResolver, SigningKeysResolver>();
```
