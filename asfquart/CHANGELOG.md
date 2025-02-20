Changes in 0.1.10:
 - OAuth redirects have switch to using the Refresh HTTP header instead of a 30x response, allowing
   samesite cookies to work with external OAuth providers when the hostname differs.

Changes in 0.1.9:
 - added the `metadata` dict to session objects where apps can store session-specific instructions
 - tightened file modes for the app secrets file. it will now fail to create if it already exists, and modes are better enforced
 - Switch from `asyncinotify` to `watchfiles` to allow for functionality on other platforms, such as macOS
 - Updated quart dependency (0.19.4 -> 0.20.0)

Changes in 0.1.8:
- Improved compatibility with Hypercorn which uses a backport of ExceptionGroup
  to function. This provides Python 3.10 compatibility.
- Adjust Python dependency allow >= 3.10, and all later 3.x versions, rather than
  just 3.10, 3.11, and 3.12.

Changes in 0.1.7:
- Fixed the PAT handler missing asyncio library import
- auth.require can now require role account as a type

Changes in 0.1.6:
- Custom token handler can now be set for sessions obtained through bearer tokens
- Session cookies are now secured by default (SameSite=Strict, HttpOnly, Secure=True)
