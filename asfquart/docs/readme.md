# Bootstrapping asfquart

## Constructing the base quart app

~~~python
import asfquart

def main():
    app = asfquart.construct("name_of_app")
    return app

if __name__ == "__main__":
    app = main()
~~~

Other modules in the app will use:
~~~
import asfquart
APP = asfquart.APP

@APP.some_decorator
async def some_endpoint():
    return do_something()
~~~

## See also (WIP):

- [Setting up OAuth](oauth.md)
- [Authentication, Authorization, and Access](auth.md)
- [Simplified EZT templating](templates.md)
