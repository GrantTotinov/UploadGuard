using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace UploadGuard;

/// <summary>
/// Validates every file in the request form against a policy before an MVC action runs. Invalid files produce a
/// 400 validation problem with one error per form field. For Minimal APIs use <c>WithUploadPolicy</c>.
/// </summary>
/// <param name="policy">The policy name.</param>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class UploadPolicyAttribute(string policy) : Attribute, IAsyncActionFilter
{
    /// <summary>Gets the policy name.</summary>
    public string Policy { get; } = policy;

    /// <inheritdoc />
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        var http = context.HttpContext;
        var pipeline = http.RequestServices.GetRequiredService<UploadPipeline>();
        var errors = await pipeline.ValidateFormAsync(http.Request, Policy, http.RequestAborted);
        if (errors is null)
        {
            await next();
            return;
        }

        foreach (var (field, messages) in errors)
        {
            foreach (var message in messages)
            {
                context.ModelState.AddModelError(field, message);
            }
        }

        var problem = http.RequestServices.GetRequiredService<ProblemDetailsFactory>()
            .CreateValidationProblemDetails(http, context.ModelState);
        context.Result = new ObjectResult(problem) { StatusCode = problem.Status };
    }
}
