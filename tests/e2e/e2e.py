import sys,asyncio,threading,http.server,socketserver,os,tempfile,time
from playwright.async_api import async_playwright
EXT=sys.argv[1]; PORT=int(os.environ.get("P","18765"))
class H(http.server.SimpleHTTPRequestHandler):
  def do_GET(self):
    b=open('login.html','rb').read(); self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers(); self.wfile.write(b)
  def log_message(self,*a): pass
socketserver.ThreadingTCPServer.allow_reuse_address=True
srv=socketserver.ThreadingTCPServer(('127.0.0.1',PORT),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
B64='p2ANqtz-8xYz3kQwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcdEFGH_ij'
LONG='CJbjp7Snv90lH5CyQwErTyUiOpAsDfGhJkLzXcVbNm12345'
CASES=[('hubspot_real','/firstorder.php?utm_medium=email&_hsenc='+B64+'&_hsmi=330925143'),
       ('hubspot_fake_hsenc','/firstorder.php?utm_medium=email&_hsenc='+LONG),
       ('spear_id','/firstorder.php?id='+LONG),
       ('clean','/firstorder.php?utm_medium=email')]
async def main():
  async with async_playwright() as p:
    ud=tempfile.mkdtemp()
    ctx=await p.chromium.launch_persistent_context(ud,channel='chromium',headless=True,args=[f'--disable-extensions-except={EXT}',f'--load-extension={EXT}','--host-resolver-rules=MAP *.e2e.test 127.0.0.1'])
    await asyncio.sleep(3)
    for name,path in CASES:
      pg=await ctx.new_page(); url=f'http://app.cosec.e2e.test:{PORT}{path}'
      try: await pg.goto(url,wait_until='load',timeout=15000)
      except Exception as e: pass
      await asyncio.sleep(6)
      final=pg.url
      print(f"{name:22s} {'BLOCKED' if 'blocked.html' in final else 'open   '} {final[:110]}")
      await pg.close()
    await ctx.close()
asyncio.run(main())
