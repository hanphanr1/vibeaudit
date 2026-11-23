import type { SourceFile } from '../loader';
import type { Hit } from '../types';
import { sourceHit } from './secrets';

const missingHeaders = [
  ['config-csp', 'Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"],
  ['config-frame', 'X-Frame-Options', 'DENY'],
  ['config-nosniff', 'X-Content-Type-Options', 'nosniff'],
] as const;

export function analyzeConfig(file: SourceFile): Hit[] {
  const name = file.path.split('/').at(-1)!;
  const hits: Hit[] = [];
  if (/^next\.config\.[cm]?[jt]s$/.test(name)) {
    for (const [id, header, value] of missingHeaders) {
      if (file.text.toLowerCase().includes(header.toLowerCase())) continue;
      if (id === 'config-frame' && /frame-ancestors\s+'(?:none|self)'/.test(file.text)) continue;
      hits.push(sourceHit(file,id,0,JSON.stringify({key:header,value},null,2), 'expect(response.headers.get(' + JSON.stringify(header) + ')).toBeTruthy();'));
    }
    const maps = /\bproductionBrowserSourceMaps\s*:\s*true\b/.exec(file.text);
    const wild = /\bremotePatterns\s*:\s*\[[\s\S]*?\bhostname\s*:\s*['"]\*\*?['"]/.exec(file.text);
    if (maps) hits.push(sourceHit(file,'config-sourcemaps',maps.index,'- productionBrowserSourceMaps: true,\n+ productionBrowserSourceMaps: false,','expect(productionConfig.productionBrowserSourceMaps).not.toBe(true);'));
    if (wild) hits.push(sourceHit(file,'config-image-wildcard',wild.index,'- hostname: "**"\n+ hostname: approvedImageHost','expect(imageHosts).not.toContain("**");'));
  }
  if (/^(?:SKILL\.md|\.cursorrules|AGENTS\.md|CL(?:AU)DE\.md)$/i.test(name)) {
    const control = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069]/u.exec(file.text);
    if (control) hits.push(sourceHit(file,'config-instruction-unicode',control.index,'Remove U+' + control[0].codePointAt(0)!.toString(16).toUpperCase() + ' from the referenced line.','expect(containsHiddenControls(instructions)).toBe(false);'));
    const suspicious = /^(?!\s*(?:never\b|do not\b|don.t\b|avoid\b|reject\b))(?=.*(?:\.env(?:\b|\.)|\.ssh\b|private\s+keys?))(?=.*(?:curl\b|fetch\s*\(|upload\b|send\b|post\b))(?=.*https?:\/\/).+$/im.exec(file.text);
    if (suspicious) hits.push(sourceHit(file,'config-instruction-export',suspicious.index,'Replace this instruction with: Keep credentials local. Report variable names only.','expect(auditInstructions(instructions)).not.toContain("config-instruction-export");','[Instruction withheld: secret sources and an outbound destination]'));
  }
  if (name === 'package.json') {
    try {
      const { scripts } = JSON.parse(file.text);
      for (const hook of ['preinstall','postinstall','install']) {
        const command: unknown = scripts?.[hook];
        if (typeof command !== 'string' || /^\s*(?::\s+)?#/.test(command)) continue;
        const id = /\b(curl|wget)\b.*\|\s*(?:(?:\/bin\/)?(?:ba)?sh|powershell)\b/i.test(command) ? 'config-install-pipe'
          : /\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|enc|encodedcommand)\s/i.test(command) ? 'config-install-encoded' : undefined;
        if (id) hits.push(sourceHit(file,id,Math.max(0,file.text.indexOf(JSON.stringify(hook))),'Remove scripts.' + hook + ' from package.json; use a reviewed local script if setup is necessary.','expect(packageManifest.scripts?.' + hook + ').toBeUndefined();','"' + hook + '": "[command withheld]"'));
      }
    } catch { /* malformed manifests cannot define runnable hooks */ }
  }
  return hits;
}
