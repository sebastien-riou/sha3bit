************
Installation
************
The package provides a command line tool and a Python3 API.

Command line tool
=================
Install with `pipx <https://pipx.pypa.io>`_, it puts the ``sha3bit``
command in its own isolated environment:

.. code-block:: bash

    pipx install sha3bit

The message is given as a hex string:

.. code-block:: console

    $ sha3bit --sha3-256 616263
    3A 98 5D A7 4F E2 25 B2 04 5C 17 2D 6B D3 90 BD 85 5F 08 6E 3E 9D 52 5B 46 BF E2 45 11 43 15 32

See :doc:`examples_cli` for more examples.

If ``pipx`` is missing, on Debian/Ubuntu:

.. code-block:: bash

    sudo apt install pipx && pipx ensurepath

Python API
==========
Add it to your project with `pipenv <https://pipenv.pypa.io>`_:

.. code-block:: bash

    pipenv install sha3bit

If ``pipenv`` is missing:

.. code-block:: bash

    pipx install pipenv
