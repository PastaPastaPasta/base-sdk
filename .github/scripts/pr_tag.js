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

    await sync(Labels.NEEDS_REBASE, detail.mergeable_state === "dirty");
  }
};
