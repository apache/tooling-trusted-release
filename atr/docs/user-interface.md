# 3.5. User interface

**Up**: `3.` [Developer guide](developer-guide)

**Prev**: `3.4.` [Storage interface](storage-interface)

**Next**: `3.6.` [Tasks](tasks)

**Sections**:

* [Introduction](#introduction)
* [Jinja2 templates](#jinja2-templates)
* [Forms](#forms)
* [Programmatic HTML](#programmatic-html)
* [The htm.Block class](#the-htmblock-class)
* [How a route renders UI](#how-a-route-renders-ui)

## Introduction

ATR uses server-side rendering almost exclusively: the server generates HTML and sends it to the browser, which displays it. We try to avoid client-side scripting, and in the rare cases where we need dynamic front end components we use plain TypeScript without recourse to any third party framework. (We have some JavaScript too, but we aim to use TypeScript only.) Sometimes we incur a full page load where perhaps it would be more ideal to update a fragment of the DOM in place, but page loads are very fast in modern browsers, so this is less of an issue than it would have been a decade ago.

The UI is built from three main pieces: [Jinja2](https://jinja.palletsprojects.com/) for templates, [WTForms](https://wtforms.readthedocs.io/) for HTML forms, and [htpy](https://htpy.dev/) for programmatic HTML generation. We style everything with [Bootstrap](https://getbootstrap.com/), which we customize slightly.

## Jinja2 templates

Templates live in [`templates/`](/ref/atr/templates/). Each template is a Jinja2 file that defines HTML structure with placeholders for dynamic content. Route handlers render templates by calling [`template.render`](/ref/atr/template.py:render), which is an alias for [`template.render_sync`](/ref/atr/template.py:render_sync). The function is asynchronous and takes a template name plus keyword arguments for the template variables.

Here is an example from [`get/keys.py`](/ref/atr/get/keys.py:add):

```python
return await template.render(
    "keys-add.html",
    asf_id=session.uid,
    user_committees=participant_of_committees,
    form=form,
    key_info=key_info,
    algorithms=shared.algorithms,
)
```

The template receives these variables and can access them directly. If you pass a variable called `form`, the template can use `{{ form }}` to render it. [Jinja2 has control structures](https://jinja.palletsprojects.com/en/stable/templates/#list-of-control-structures) like `{% for %}` and `{% if %}`, which you use when iterating over data or conditionally showing content.

Templates are loaded into memory at server startup by [`preload.setup_template_preloading`](/ref/atr/preload.py:setup_template_preloading). This means that changing a template requires restarting the server in development, which can be configured to happen automatically, but it also means that rendering is fast because we never do a disk read during request handling. The preloading scans [`templates/`](/ref/atr/templates/) recursively and caches every file.

Template rendering happens in a thread pool to avoid blocking the async event loop. The function [`_render_in_thread`](/ref/atr/template.py:_render_in_thread) uses `asyncio.to_thread` to execute Jinja2's synchronous `render` method.

## Forms

HTML forms in ATR are handled by [WTForms](https://wtforms.readthedocs.io/), accessed through our [`forms`](/ref/atr/forms.py) module. Each form is a class that inherits from [`forms.Typed`](/ref/atr/forms.py:Typed), which itself inherits from `QuartForm` in [Quart-WTF](https://quart-wtf.readthedocs.io/). Form fields are class attributes created using helper functions from the `forms` module.

Here is a typical form definition from [`shared/keys.py`](/ref/atr/shared/keys.py:AddOpenPGPKeyForm):

```python
class AddOpenPGPKeyForm(forms.Typed):
    public_key = forms.textarea(
        "Public OpenPGP key",
        placeholder="Paste your ASCII-armored public OpenPGP key here...",
        description="Your public key should be in ASCII-armored format, starting with"
        ' "-----BEGIN PGP PUBLIC KEY BLOCK-----"',
    )
    selected_committees = forms.checkboxes(
        "Associate key with committees",
        description="Select the committees with which to associate your key.",
    )
    submit = forms.submit("Add OpenPGP key")
```

The helper functions like [`forms.textarea`](/ref/atr/forms.py:textarea), [`forms.checkboxes`](/ref/atr/forms.py:checkboxes), and [`forms.submit`](/ref/atr/forms.py:submit) create WTForms field objects with appropriate validators. The first argument is always the label text. Optional fields take `optional=True`, and you can provide placeholders, descriptions, and other field-specific options. If you do not pass `optional=True`, the field is required by default. The [`forms.string`](/ref/atr/forms.py:string) function adds `REQUIRED` to the validators, while [`forms.optional`](/ref/atr/forms.py:optional) adds `OPTIONAL`.

To use a form in a route, create it with `await FormClass.create_form()`. For POST requests, pass `data=await quart.request.form` to populate it with the submitted data. Then validate with `await form.validate_on_submit()`. If validation passes, you extract data from `form.field_name.data` and proceed. If validation fails, re-render the template with the form object, which will then display error messages.

The [`forms`](/ref/atr/forms.py) module also provides rendering functions that generate Bootstrap-styled HTML. The function [`forms.render_columns`](/ref/atr/forms.py:render_columns) creates a two-column layout with labels on the left and inputs on the right. The function [`forms.render_simple`](/ref/atr/forms.py:render_simple) creates a simpler vertical layout. The function [`forms.render_table`](/ref/atr/forms.py:render_table) puts the form inside a table. All three functions return htpy elements, which you can embed in templates or return directly from route handlers.

## Programmatic HTML

Sometimes you need to generate HTML in Python rather than in a template. For this we use [htpy](https://htpy.dev/), which provides a Python API for building HTML elements. You import `htpy` and then use it like this:

```python
import htpy

element = htpy.div(".container")[
    htpy.h1["Release Candidate"],
    htpy.p["This is a release candidate."],
]
```

The square brackets syntax is how htpy accepts children. The parentheses syntax is for attributes. If you want a div with an id, you write `htpy.div(id="content")`. If you want a div with a class, you can use CSS selector syntax like `htpy.div(".my-class")` or you can use `htpy.div(class_="my-class")`, remembering to use the underscore in `class_`.

You can nest elements arbitrarily, mix strings and elements, and pass lists of elements. Converting an htpy element to a string renders it as HTML. Templates can therefore render htpy elements directly by passing them as variables.

The htpy library provides type annotations for HTML elements. It does not validate attribute names or values, so you can pass nonsensical attributes without error. We plan to fix this by adding stricter types in our `htm` wrapper. The main benefit to using `htpy` (via `htm`) is having a clean Python API for HTML generation rather than concatenating strings or using templating.

## The htm.Block class

The ATR [`htm`](/ref/atr/htm.py) module extends htpy with a [`Block`](/ref/atr/htm.py:Block) class that makes it easier to build complex HTML structures incrementally. You create a block, append elements to it, and then collect them into a final element. Here is the typical usage pattern:

```python
import atr.htm as htm

div = htm.Block()
div.h1["Release Information"]
div.p["The release was created on ", release.created.isoformat(), "."]
if release.released:
    div.p["It was published on ", release.released.isoformat(), "."]
return div.collect()
```

The block class provides properties for common HTML elements like `h1`, `h2`, `p`, `div`, `ul`, and so on. When you access these properties, you get back a [`BlockElementCallable`](/ref/atr/htm.py:BlockElementCallable), which you can call to create an element with attributes or use square brackets to add grandchildren of the block. The element is automatically appended to the block's internal list of children.

The `collect` method assembles all of the elements into a single htpy element. If you created the block with an outer element like `htm.Block(htpy.div(".container"))`, that element wraps all the children. If you created the block with no outer element, `collect` wraps everything in a div. You can also pass a `separator` argument to `collect`, which inserts a text separator between elements.

The block class is useful when you are building HTML in a loop or when you have conditional elements. Instead of managing a list of elements manually, you can let the block class do it for you: append elements as you go, and at the end call `collect` to get the final result. This is cleaner than concatenating strings or maintaining lists yourself.

The block class also adds a `data-src` attribute to elements, which records which function created the element. If you see an element in the browser inspector with `data-src="atr.get.keys:keys"`, you know that it came from the `keys` function in `get/keys.py`. The source is extracted automatically using [`log.caller_name`](/ref/atr/log.py:caller_name).

## How a route renders UI

A typical route that renders UI first authenticates the user, loads data from the database, creates and validates a form if necessary, and renders a template with the data and form. Here is a simplified example from [`get/keys.py`](/ref/atr/get/keys.py:add):

```python
@route.committer("/keys/add", methods=["GET", "POST"])
async def add(session: route.CommitterSession) -> str:
    async with storage.write() as write:
        participant_of_committees = await write.participant_of_committees()

    committee_choices: forms.Choices = [
        (c.name, c.display_name or c.name)
        for c in participant_of_committees
    ]

    form = await AddOpenPGPKeyForm.create_form(
        data=(await quart.request.form) if (quart.request.method == "POST") else None
    )
    forms.choices(form.selected_committees, committee_choices)

    if await form.validate_on_submit():
        # Process the form data
        # ...
        await quart.flash(f"OpenPGP key added successfully.", "success")
        form = await AddOpenPGPKeyForm.create_form()
        forms.choices(form.selected_committees, committee_choices)

    return await template.render(
        "keys-add.html",
        asf_id=session.uid,
        user_committees=participant_of_committees,
        form=form,
    )
```

The route is decorated with `@route.committer`, which ensures that the route fails before the function is even entered if authentication fails. The function receives a `session` object, which is an instance of [`route.CommitterSession`](/ref/atr/route.py:CommitterSession) with a range of useful properties and methods. The function then loads data, creates a form, checks if the request is a POST, and either processes the form or displays it. After successful processing, it creates a fresh form to clear the data. At the end, it renders a template with all of the variables that the template needs.

The template receives the form object and renders it by passing it to one of the `forms.render_*` functions. We previously used Jinja2 macros for this, but are migrating to the new rendering functions in Python (e.g. in [`get/distribution.py`](/ref/atr/get/distribution.py) and [`get/ignores.py`](/ref/atr/get/ignores.py)). The template also receives other data like `asf_id` and `user_committees`, which it uses to display information or make decisions about what to show.

If you use the programmatic rendering functions from [`forms`](/ref/atr/forms.py), you can skip the template entirely. These functions return htpy elements, which you can combine with other htpy elements and return directly from the route, which is often useful for admin routes, for example. You can also use [`template.blank`](/ref/atr/template.py:blank), which renders a minimal template with just a title and content area. This is useful for simple pages that do not need the full template machinery.

Bootstrap CSS classes are applied automatically by the form rendering functions. The functions use classes like `form-control`, `form-select`, `btn-primary`, `is-invalid`, and `invalid-feedback`. We currently use Bootstrap 5. If you generate HTML manually with htpy, you can apply Bootstrap classes yourself by using the CSS selector syntax like `htpy.div(".container")` or the class attribute like `htpy.div(class_="container")`.
