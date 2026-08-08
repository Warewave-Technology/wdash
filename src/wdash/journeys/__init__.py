"""
Browser journeys: a check that is a sequence rather than a request.

The step language lives here rather than in `agent/` because both sides need
it. The server validates a journey and renders it on a page; the agent
executes it. One definition, so a journey that the form accepted cannot be one
the agent does not understand.
"""

from .steps import (
    MAX_STEPS, SECRET_PATTERN, STEP_KINDS, Step, StepError, describe, parse,
    resolve, secret_names,
)

__all__ = ["MAX_STEPS", "SECRET_PATTERN", "STEP_KINDS", "Step", "StepError",
           "describe", "parse", "resolve", "secret_names"]
