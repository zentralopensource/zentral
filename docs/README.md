# Zentral's documentation

(these instructions are adapted from the excellent [django/docs](https://github.com/django/django/blob/master/docs/))

The documentation in this tree uses [Markdow]('https://github.com/rtfd/recommonmark') and the [Sphinx documentation system](http://sphinx-doc.org/).
This allows it to be built into other forms for easier viewing and browsing.

To generate the HTML version of the docs:

 * Install Sphinx and recommonmark (using ``pip install Sphinx recommonmark`` or some other method)

 * In this directory, use the command ``make html`` (or ``make.bat html`` on Windows)

The documentation in _build/html/index.html can then be viewed in a web browser.
