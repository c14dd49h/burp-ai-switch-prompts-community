# Debug Mode Detection

## Objective
Identify applications running in debug or development mode in production environments, which can expose sensitive functionality and information.

## Instructions

### 1. Framework-Specific Debug Indicators

**Django:**
```http
# Debug toolbar visible
# Yellow error pages with full stack traces
# Settings exposed: DEBUG = True
```

**Laravel:**
```http
# Whoops error handler
# APP_DEBUG = true
# Detailed exception pages
```

**Spring Boot:**
```http
# Actuator endpoints exposed
/actuator/health
/actuator/env
/actuator/configprops
```

**Express.js:**
```http
# Stack traces in responses
# NODE_ENV !== 'production'
```

**Ruby on Rails:**
```http
# Better Errors gem active
# Web console accessible
# Full stack traces
```

**ASP.NET:**
```http
# customErrors mode="Off"
# Yellow screen of death
# Full exception details
```

### 2. Debug Endpoints

**Common debug URLs:**
```
/debug
/debug/default/view
/debug/pprof/
/_debug
/__debug__
/console
/shell
/phpinfo.php
/info.php
/test.php
/.env
/config
/status
```

### 3. Debug Headers

**Indicators in headers:**
```http
X-Debug-Token: xxx
X-Debug-Token-Link: /_profiler/xxx
X-Debug-Info: xxx
X-Runtime: 0.003141
X-Request-Id: xxx
```

### 4. Profiler and Toolbar Detection

**Debug toolbars:**
- Django Debug Toolbar (/__debug__)
- Symfony Profiler (/_profiler)
- Laravel Debugbar
- Rails Web Console

**Check for:**
```html
<!-- Debug toolbar HTML -->
<div id="django-debug-toolbar">
<div class="sf-toolbar">
```

### 5. Exposed Configuration

**Environment files:**
```
/.env
/.env.local
/.env.development
/config.php
/settings.py
/application.yml
/application.properties
```

**Content indicators:**
```
APP_ENV=development
DEBUG=true
NODE_ENV=development
FLASK_DEBUG=1
```

### 6. Development Dependencies

**Check for development tools:**
```
/webpack-dev-server
/hot-update.json
/__webpack_hmr
/livereload.js
/browser-sync
```

### 7. Source Maps

**Exposed source maps:**
```
/app.js.map
/main.bundle.js.map
/styles.css.map
```

**Impact:**
- Original source code exposure
- Variable/function names
- Comments and documentation

### 8. Database Debug Interfaces

**Exposed DB tools:**
```
/phpmyadmin
/adminer.php
/pgadmin
/mongo-express
/redis-commander
```

### 9. API Documentation

**Auto-generated docs in production:**
```
/swagger
/swagger-ui
/api-docs
/graphql (with introspection)
/playground
/graphiql
```

### 10. Console and REPL Access

**Interactive consoles:**
```
# Rails web console
# Django shell
# PHP interactive mode
# Node.js REPL
```

**Check for console in error pages:**
```python
# Werkzeug debugger (Flask)
# Allows code execution!
```

### 11. Risk Assessment

**High Risk:**
- Interactive debug consoles (RCE potential)
- Exposed environment variables with secrets
- Database admin interfaces

**Medium Risk:**
- Detailed stack traces
- Source maps
- Profiler data

**Low Risk:**
- Version information
- Request timing data

### 12. Document the Finding

**Create OBSERVATION finding with:**
- Debug feature identified
- URL/location
- Information/functionality exposed
- Risk level
- Recommendation to disable

## Remediation Guidance

**General:**
- Set DEBUG=false in production
- Remove debug dependencies from production builds
- Use environment-specific configurations
- Restrict access to debug endpoints
- Disable source maps in production

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Check debug endpoints
- `sitemap_json`: Analyze discovered endpoints
- `find_reflected`: Search for debug indicators

### Chrome
- `evaluate_script`: Check for debug objects in global scope
- `list_console_messages`: Look for debug logs

## Keywords
debug mode, development mode, profiler, debug toolbar

## References
- OWASP Testing for Debug Code
- Framework-specific security hardening guides
