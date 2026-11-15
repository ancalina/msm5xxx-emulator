param([Parameter(Mandatory=$true)][string]$OutputDirectory,
      [string]$Version='', [string]$BuildDate='', [string]$BuildCommit='')
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$options=@('--platform','WIN X64','--out',$OutputDirectory)
if ($Version) { $options+=@('--version',$Version) }
if ($BuildDate) { $options+=@('--date',$BuildDate) }
if ($BuildCommit) { $options+=@('--commit',$BuildCommit) }
& python "$PSScriptRoot\chip_icon.py" @options
if ($LASTEXITCODE) { throw 'Icon SVG generation failed.' }
Add-Type -AssemblyName System.Drawing
# The shared generator emits only stroked M/L paths and circles over a chip plate.
Add-Type -ReferencedAssemblies System.Drawing,System.Xml -TypeDefinition @'
using System;
using System.IO;
using System.Xml;
using System.Globalization;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Text.RegularExpressions;
public static class ChipIcon {
    static float N(string s) { return float.Parse(s, CultureInfo.InvariantCulture); }
    static Bitmap Render(string file, int size) {
        var image=new Bitmap(size,size,PixelFormat.Format32bppArgb);
        using(var g=Graphics.FromImage(image)) {
            g.SmoothingMode=SmoothingMode.AntiAlias;
            g.ScaleTransform(size/1024f,size/1024f);
            using(var plate=new LinearGradientBrush(new Rectangle(0,0,1024,1024),Color.FromArgb(70,73,77),Color.FromArgb(44,46,49),90f)) g.FillRectangle(plate,0,0,1024,1024);
            var xml=new XmlDocument(); xml.Load(file);
            var ns=new XmlNamespaceManager(xml.NameTable);ns.AddNamespace("s","http://www.w3.org/2000/svg");
            foreach(XmlElement group in xml.SelectNodes("/s:svg/s:g",ns)) {
                foreach(XmlElement path in group.SelectNodes("s:path",ns)) {
                    var transform=Regex.Match(path.GetAttribute("transform"),@"translate\(([-\d.]+) ([-\d.]+)\) scale\(([-\d.]+) ([-\d.]+)\)");
                    float x=N(transform.Groups[1].Value), y=N(transform.Groups[2].Value), sx=N(transform.Groups[3].Value), sy=N(transform.Groups[4].Value);
                    using(var pen=new Pen(ColorTranslator.FromHtml(group.GetAttribute("stroke")),N(group.GetAttribute("stroke-width"))*Math.Abs(sx))) {
                        pen.StartCap=pen.EndCap=LineCap.Round;pen.LineJoin=LineJoin.Round;
                        var tokens=Regex.Matches(path.GetAttribute("d"),@"[ML]|-?\d+(?:\.\d+)?");
                        float px=0,py=0;string command="M";
                        for(int i=0;i<tokens.Count;) {
                            if(tokens[i].Value=="M" || tokens[i].Value=="L") { command=tokens[i++].Value; }
                            float nx=x+N(tokens[i++].Value)*sx, ny=y+N(tokens[i++].Value)*sy;
                            if(command=="L")g.DrawLine(pen,px,py,nx,ny);px=nx;py=ny;
                        }
                    }
                }
            }
            foreach(XmlElement dot in xml.SelectNodes("/s:svg/s:circle",ns)) {
                float r=N(dot.GetAttribute("r"));
                using(var b=new SolidBrush(ColorTranslator.FromHtml(dot.GetAttribute("fill"))))g.FillEllipse(b,N(dot.GetAttribute("cx"))-r,N(dot.GetAttribute("cy"))-r,2*r,2*r);
            }
        }
        return image;
    }
    public static void Write(string folder,bool simple) {
        int[] sizes={16,20,24,32,40,48,64,128,256}; var frames=new List<byte[]>();
        foreach(int size in sizes)using(var bitmap=Render(Path.Combine(folder,simple||size<=48?"small.svg":"full.svg"),size))using(var stream=new MemoryStream()){bitmap.Save(stream,ImageFormat.Png);frames.Add(stream.ToArray());}
        using(var writer=new BinaryWriter(File.Create(Path.Combine(folder,simple?"simple.ico":"full.ico")))) {
            writer.Write((ushort)0);writer.Write((ushort)1);writer.Write((ushort)sizes.Length);int offset=6+16*sizes.Length;
            for(int i=0;i<sizes.Length;i++){writer.Write((byte)(sizes[i]==256?0:sizes[i]));writer.Write((byte)(sizes[i]==256?0:sizes[i]));writer.Write((ushort)0);writer.Write((ushort)1);writer.Write((ushort)32);writer.Write(frames[i].Length);writer.Write(offset);offset+=frames[i].Length;}
            foreach(var frame in frames)writer.Write(frame);
        }
    }
}
'@
[ChipIcon]::Write($OutputDirectory,$false)
[ChipIcon]::Write($OutputDirectory,$true)
Copy-Item "$PSScriptRoot\HersheySans1.svg" "$OutputDirectory\HersheySans1.svg" -Force
