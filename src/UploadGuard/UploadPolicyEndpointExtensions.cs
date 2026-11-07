using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using UploadGuard;

namespace Microsoft.AspNetCore.Builder;

/// <summary>Validates uploads on Minimal API endpoints.</summary>
public static class UploadPolicyEndpointExtensions
{
    /// <summary>
    /// Validates every file in the request form against <paramref name="policy"/> before the handler runs. Invalid
    /// files produce a 400 validation problem with one error per form field; the handler is not called.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint or group builder.</typeparam>
    /// <param name="builder">The builder.</param>
    /// <param name="policy">The policy name. Checked when the endpoint is built.</param>
    /// <returns>The builder.</returns>
    public static TBuilder WithUploadPolicy<TBuilder>(this TBuilder builder, string policy)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentException.ThrowIfNullOrEmpty(policy);
        return builder.AddEndpointFilterFactory((context, next) =>
        {
            var pipeline = context.ApplicationServices.GetRequiredService<UploadPipeline>();
            pipeline.GetPolicy(policy);
            return async invocation =>
            {
                var http = invocation.HttpContext;
                var errors = await pipeline.ValidateFormAsync(http.Request, policy, http.RequestAborted);
                return errors is null ? await next(invocation) : TypedResults.ValidationProblem(errors);
            };
        });
    }
}
