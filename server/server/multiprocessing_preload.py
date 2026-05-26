"""Preloaded into the multiprocessing forkserver process so that child
processes have Django's app registry ready.

See server/base/management/commands/runworkers.py
"""
import django

django.setup()
