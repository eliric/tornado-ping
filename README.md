# tornado-ping
Asynchronous ping for python-Tornado that can ping multiple ips concurrently.<br>
No subprocess required.<br>
Support coroutine.<br>
# usage
<br>
```python
import torping
import tornado.ioloop

if __name__ == '__main__':
    tp = torping.Torping()
    tornado.ioloop.IOLoop.current().run_sync(lambda:tp.ping("www.bing.com" , quiet=False))
```
