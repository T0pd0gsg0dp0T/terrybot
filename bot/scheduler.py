"""
bot/scheduler.py — APScheduler cron runner for Terrybot.

Schedules recurring jobs that inject messages into sessions.
Uses DeliveryManager to route responses back to the right channel.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

if TYPE_CHECKING:
    from agent.runner import LLMRunner
    from bot.delivery import DeliveryManager
    from config import Settings, SchedulerJob


class TerryScheduler:
    """Wraps APScheduler AsyncIOScheduler with Terrybot job definitions."""

    def __init__(
        self,
        settings: "Settings",
        runner: "LLMRunner",
        delivery: "DeliveryManager",
    ) -> None:
        self._runner = runner
        self._delivery = delivery
        self._scheduler = AsyncIOScheduler()

        for job in settings.scheduler.jobs:
            try:
                trigger = CronTrigger.from_crontab(job.cron)
                self._scheduler.add_job(
                    self._run_job,
                    trigger,
                    args=[job],
                    id=job.id,
                    name=f"terrybot:{job.id}",
                    replace_existing=True,
                )
                print(f"[scheduler] Registered job '{job.id}' cron={job.cron!r}", file=sys.stderr)
            except Exception as e:
                print(
                    f"[scheduler] Failed to register job '{job.id}': {type(e).__name__}: {e}",
                    file=sys.stderr,
                )

    @property
    def underlying(self) -> AsyncIOScheduler:
        """Expose the underlying APScheduler for adding jobs (e.g. Gmail poll)."""
        return self._scheduler

    def start(self) -> None:
        self._scheduler.start()
        print("[scheduler] Started.", file=sys.stderr)

    def stop(self) -> None:
        self._scheduler.shutdown(wait=False)
        print("[scheduler] Stopped.", file=sys.stderr)

    async def _run_job(self, job: "SchedulerJob") -> None:
        try:
            response = await self._runner.run_turn(job.session_id, job.message)
            await self._delivery.deliver(job.session_id, response)
        except Exception as e:
            print(
                f"[scheduler] Job '{job.id}' failed: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
