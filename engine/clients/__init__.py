# clients/__init__.py

# This file makes the 'clients' directory a Python package.
# It can be used to define package-level variables or imports.

# It's common to import key classes from submodules here
# to make them directly accessible from the package level.
# For example, if llm_client.py defines an AbstractLLMClient class,
# you might import it like this:
# from .llm_client import AbstractLLMClient

# Currently, llm_client.py defines the abstract base class and concrete implementations.
# We can expose them directly for easier use.
try:
    from .llm_client import LLMClient, OpenAIClient, AnthropicClient, GroqClient
except ImportError as e:
    # Log or handle the import error if a submodule is missing or incorrectly structured.
    print(f"Error importing from clients submodule: {e}")
    raise

# You can also define package-level metadata if needed, e.g.:
__version__ = "0.1.0"
__author__ = "Your Name"