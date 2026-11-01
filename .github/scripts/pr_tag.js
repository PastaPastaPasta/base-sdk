/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

const { BASE_BRANCH, getPullDetail, listOpenPulls } = require("./util");

const STALE_DAYS = 60;

/** @enum {string} */
const Labels = {
  BEHIND: "status:behind",
  HALT_CI: "tag:halt-ci",
  NEEDS_REBASE: "status:needs-rebase",
  STALE: "status:stale",
};

// Repository roles allowed to halt a pull request's runs.
const MAINTAINER_ROLES = ["admin", "maintain"];

// A pull request owns runs from these events, never manual or scheduled ones.
const PR_EVENTS = ["pull_request", "push"];

/**
 * Syncs the status labels of every open pull request into `develop`.
 *
 * @param {{ github: import("@actions/github").getOctokit, context: import("@actions/github").context }} params
 */
async function tag({ github, context }) {
  const { owner, repo } = context.repo;
  const pulls = await listOpenPulls({ github, owner, repo });
  const now = new Date();

  for (const pr of pulls) {
    const labels = pr.labels.map((l) => l.name);
    const issue = { owner, repo, issue_number: pr.number };
    // Adds or removes a label so its presence matches `want`.
    const sync = async (name, want) => {
      if (want === labels.includes(name)) {
        return;
      }
      // A label removed by hand after the listing is already gone.
      await (want
        ? github.rest.issues.addLabels({ ...issue, labels: [name] })
        : github.rest.issues.removeLabel({ ...issue, name }).catch((error) => {
            if (error.status !== 404) {
              throw error;
            }
          }));
      console.log(`PR #${pr.number}: ${want ? "tagged" : "removed"} ${name}`);
    };

    const { data: head } = await github.rest.repos.getCommit({ owner, repo, ref: pr.head.sha });
    const idleDays = (now - new Date(head.commit.committer.date)) / (1000 * 60 * 60 * 24);
    await sync(Labels.STALE, idleDays >= STALE_DAYS);

    const detail = await getPullDetail({ github, owner, repo, prNumber: pr.number });

    if (detail.mergeable_state === "unknown") {
      continue;
    }

    const hasConflicts = detail.mergeable_state === "dirty";
    await sync(Labels.NEEDS_REBASE, hasConflicts);

    // Only a clean pull request is compared, as a conflict needs a rebase.
    let isBehind = false;
    if (!hasConflicts) {
      const { data: comparison } = await github.rest.repos.compareCommitsWithBasehead({
        owner,
        repo,
        basehead: `${BASE_BRANCH}...${pr.head.sha}`,
        per_page: 1,
      });
      isBehind = comparison.behind_by > 0;
    }
    await sync(Labels.BEHIND, isBehind);
  }
}

/**
 * Cancels the unfinished runs of a pull request's head commit once a
 * maintainer applies the halt label.
 *
 * @param {{ github: any, context: import("@actions/github").context, core: any }} params
 */
async function halt({ github, context, core }) {
  const { owner, repo } = context.repo;
  const { pull_request: pr, sender } = context.payload;

  // Clearing the label lets a maintainer apply it again to halt later pushes.
  await github.rest.issues
    .removeLabel({ owner, repo, issue_number: pr.number, name: Labels.HALT_CI })
    .catch((error) => {
      if (error.status !== 404) {
        throw error;
      }
    });

  const { data: level } = await github.rest.repos.getCollaboratorPermissionLevel({
    owner,
    repo,
    username: sender.login,
  });
  if (!MAINTAINER_ROLES.includes(level.role_name)) {
    core.notice(`${sender.login} is not a maintainer, so ${Labels.HALT_CI} is ignored`);
    return;
  }

  // A deleted fork leaves no repository to match the runs against.
  const headRepo = pr.head.repo?.full_name;
  if (!headRepo) {
    core.notice(`PR #${pr.number} has no head repository, so no runs are cancelled`);
    return;
  }

  // A protected branch's pushes belong to the branch, not to its pull requests.
  let events = PR_EVENTS;
  if (headRepo === `${owner}/${repo}`) {
    const { data: branch } = await github.rest.repos.getBranch({ owner, repo, branch: pr.head.ref });
    if (branch.protected) {
      events = ["pull_request"];
    }
  }

  const runs = await github.paginate(github.rest.actions.listWorkflowRunsForRepo, {
    owner,
    repo,
    branch: pr.head.ref,
    head_sha: pr.head.sha,
    per_page: 100,
  });
  for (const run of runs) {
    // Another pull request can share the commit, so match the repository.
    const owned = events.includes(run.event) && run.head_repository?.full_name === headRepo;
    if (run.status === "completed" || !owned) {
      continue;
    }
    try {
      await github.rest.actions.cancelWorkflowRun({ owner, repo, run_id: run.id });
      core.info(`PR #${pr.number}: cancelled ${run.name} (run ${run.id})`);
    } catch (error) {
      // A run that finished after it was listed refuses cancellation.
      if (error.status !== 409) {
        throw error;
      }
    }
  }
}

module.exports = { tag, halt };
