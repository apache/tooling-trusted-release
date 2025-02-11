# Simplified EZT templating

**asfquart** has built-in decorators to apply an EZT template to a route/handler
to generate an HTML response page from a "data dictionary".

EZT will take a template, and a data dictionary as inputs/value for that
template, to produce an HTML page. The decorator specifies the template,
and the function returns that data dictionary. These are combined and
used as the page response for the route/endpoint.

~~~python
import asfquart
APP = asfquart.APP

@APP.use_template('templates/example.ezt')
async def page_example():
    data = {
        'title': 'Example page',
        'count': 42,
        }
    return data
~~~

The `APP.use_template()` decorator takes an EZT Template instance, or
a path to a source file. For the latter, it will install a "watcher" on
that file. Should it change, the template will be automatically reloaded
immediately. Its next rendering will use the changes, and no application
restart is necessary.

The path form of `use_template()` takes a path relative to `APP.app_dir`
or an absolute path.

## Templates shared among routes

There are many times when a template might be shared across several routes.
In such a scenario, the usage demonstrated above will load the template several
times and the watcher will overwrite itself. Theoretically. This is as yet untested.
And it should not be a problem. So they say.

The preferred approach is to load the template once, register it for watching,
and then to provide the template to the use/render decorator. Example:

~~~python
import asfquart
APP = asfquart.APP

T_EXAMPLE = APP.load_template('templates/example.ezt')

@APP.use_template(T_EXAMPLE)
async def page_example():
    data = {
        'title': 'Example page',
        'count': 42,
        }
    return data

@APP.use_template(T_EXAMPLE):
async def other_example():
    ...
    return other_data
~~~
