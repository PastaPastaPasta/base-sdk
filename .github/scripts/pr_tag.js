/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

const { getPullDetail, listOpenPulls } = require("./util");

const STALE_DAYS = 60;

/** @enum {string} */
const Labels = {
  NEEDS_REBASE: "status:needs-rebase",
  STALE: "status:stale",
};

/**
 * @param {{ github: import("@actions/github").getOctokit, context: import("@actions/github").context }} params
 */
module.exports = async ({ github, context }) => {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const pulls = await listOpenPulls({ github, owner, repo });
  const now = new Date();

  for (const pr of pulls) {
    const labels = pr.labels.map((l) => l.name);

    const { data: headCommit } = await github.rest.repos.getCommit({
      owner,
      repo,
      ref: pr.head.sha,
    });
    const lastActivity = new Date(headCommit.commit.committer.date);
    const daysSinceUpdate = Math.floor((now - lastActivity) / (1000 * 60 * 60 * 24));
    const isStale = daysSinceUpdate >= STALE_DAYS;
    const hasStale = labels.includes(Labels.STALE);

    if (isStale && !hasStale) {
      await github.rest.issues.addLabels({
        owner,
        repo,
        issue_number: pr.number,
        labels: [Labels.STALE],
      });
      console.log(`PR #${pr.number}: tagged stale (${daysSinceUpdate} days)`);
    } else if (!isStale && hasStale) {
      await github.rest.issues.removeLabel({
        owner,
        repo,
        issue_number: pr.number,
        name: Labels.STALE,
      });
      console.log(`PR #${pr.number}: removed stale`);
    }

    const detail = await getPullDetail({ github, owner, repo, prNumber: pr.number });

    if (detail.mergeable_state === "unknown") {
      continue;
    }

    const hasConflicts = detail.mergeable_state === "dirty";
    const hasRebaseLabel = labels.includes(Labels.NEEDS_REBASE);

    if (hasConflicts && !hasRebaseLabel) {
      await github.rest.issues.addLabels({
        owner,
        repo,
        issue_number: pr.number,
        labels: [Labels.NEEDS_REBASE],
      });
      console.log(`PR #${pr.number}: tagged needs-rebase`);
    } else if (!hasConflicts && hasRebaseLabel) {
      await github.rest.issues.removeLabel({
        owner,
        repo,
        issue_number: pr.number,
        name: Labels.NEEDS_REBASE,
      });
      console.log(`PR #${pr.number}: removed needs-rebase`);
    }
  }
};
