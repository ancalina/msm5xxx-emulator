using Microsoft.Windows.ApplicationModel.Resources;

namespace Msm5xxx.Desktop;

public sealed class Strings
{
    public string Language { get; }
    private readonly ResourceManager manager = new();
    private readonly ResourceContext context;
    public Strings(string language = "auto")
    {
        Language = language;
        context = manager.CreateResourceContext();
        if (language is "en" or "ko") context.QualifierValues["Language"] = language == "ko" ? "ko-KR" : "en-US";
    }
    public string this[string key] => manager.MainResourceMap.GetValue("Resources/" + key, context).ValueAsString;
}
