# Unfinished Tasks

This file is the index of unfinished Harness task packets. Keep only unfinished tasks here.

Rules:
- Add a row when creating a new task packet.
- Task ids and packet directory names use `<task-seq>-<task-slug>`; `<task-seq>` defaults to 3 digits, starts at `001` for each version, and increments by 1 across all project modules and `globals` in that version.
- Before adding a row, run `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/task-seq.py next --version <version> --slug <task-slug>` and use the returned task name.
- Sequence numbers identify creation order only; they do not define the current/latest task.
- Remove the row when the task is complete.
- Do not use this file to override approved task packet immutability.
- If a new task clearly belongs to a different module than every relevant unfinished row, create a new task packet immediately; do not consider continuing unfinished tasks from other modules.
- If multiple same-module rows could match a request and the user did not identify one, stop and ask which task to use or whether to create a new sibling task packet.
- "Latest task" is valid only when the current user request explicitly points to it or `docs/modules/<module>.md` Current/Active Task points to it; do not infer it from directory order or timestamps.

| task_id | module | packet_path | status | owner | current_stage | change_ids | notes |
|---------|--------|-------------|--------|-------|---------------|------------|-------|
