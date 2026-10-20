/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

// Syncs pull request topic labels with the project board buckets, with the
// board as the source of truth. Boards and topics come from `board.json`, which maps each board
// bucket to its label.

const fs = require("node:fs");
const path = require("node:path");

const { listOpenPulls } = require("./util");

const CONFIG_PATH = path.join(__dirname, "..", "board.json");

// Color of newly created topic labels.
const TOPIC_COLOR = "1d76db";

const BOARD_QUERY = `
  query($owner: String!, $number: Int!, $field: String!, $cursor: String) {
    organization(login: $owner) {
      projectV2(number: $number) {
        id
        field(name: $field) {
          ... on ProjectV2SingleSelectField { id options { id name } }
        }
        items(first: 100, after: $cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            id
            fieldValueByName(name: $field) {
              ... on ProjectV2ItemFieldSingleSelectValue { name }
            }
            content {
              ... on PullRequest {
                number
                repository { nameWithOwner }
                labels(first: 50) { nodes { name } }
              }
            }
          }
        }
      }
    }
  }
`;

const SET_TOPIC = `
  mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
    updateProjectV2ItemFieldValue(input: {
      projectId: $project, itemId: $item, fieldId: $field,
      value: { singleSelectOptionId: $option }
    }) { projectV2Item { id } }
  }
`;

// `github` always sends the workflow token, which cannot reach organization
// projects, so board queries use `PROJECT_TOKEN` directly.
async function graphql(token, query, variables) {
  const response = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  const body = await response.json().catch(() => ({}));
  if (body.errors?.length) {
    throw new Error(body.errors.map((e) => e.message).join("; "));
  }
  if (!response.ok) {
    throw new Error(`board refused the query with ${response.status}`);
  }
  return body.data;
}

// Returns topic option ids and the *slug* pull requests on the board by number.
// Throws if the board lacks a topic option.
async function readBoard(token, { owner, number, field }, topics, slug, core) {
  const where = `${owner}/${number}`;
  const options = new Map();
  const items = new Map();
  let board;
  let cursor = null;
  do {
    const data = await graphql(token, BOARD_QUERY, { owner, number, field, cursor });
    board = data.organization?.projectV2;
    if (!board) {
      throw new Error(`${owner} states no project ${number}`);
    }
    if (!board.field?.id) {
      throw new Error(`${field} is not a single-select field on ${where}`);
    }
    for (const { id, fieldValueByName, content } of board.items.nodes) {
      // Skip issues, drafts and other repositories.
      if (content?.number && content.repository.nameWithOwner === slug) {
        items.set(content.number, {
          itemId: id,
          bucket: fieldValueByName?.name ?? null,
          labels: content.labels.nodes.map((l) => l.name),
        });
      }
    }
    const { hasNextPage, endCursor } = board.items.pageInfo;
    cursor = hasNextPage ? endCursor : null;
  } while (cursor);

  for (const { id, name } of board.field.options) {
    if (topics.has(name)) {
      options.set(name, id);
    } else {
      core.notice(`${where}: option ${name} is not a topic`);
    }
  }
  for (const topic of topics) {
    if (!options.has(topic)) {
      throw new Error(`${where}: topic ${topic} is not offered by ${field}`);
    }
  }
  return { where, id: board.id, fieldId: board.field.id, options, items };
}

// Runs a write, returning false when the target is no longer available
async function settle(write, core, what) {
  try {
    await write;
    return true;
  } catch (error) {
    if (error.status !== 404) {
      throw error;
    }
    core.info(`${what} no longer exists`);
    return false;
  }
}

// Creates missing topic labels. GitHub label names are case-insensitive, so a
// label differing only in case is renamed to the topic label.
async function mintLabels(github, owner, repo, topicLabels, core) {
  const labels = await github.paginate(github.rest.issues.listLabelsForRepo, { owner, repo, per_page: 100 });
  const held = new Map(labels.map((l) => [l.name.toLowerCase(), l.name]));
  for (const name of topicLabels) {
    const present = held.get(name.toLowerCase());
    if (present === name) {
      continue;
    }
    if (present === undefined) {
      const description = `Pull requests concerning ${name}`;
      await github.rest.issues.createLabel({ owner, repo, name, color: TOPIC_COLOR, description });
      core.info(`minted label ${name}`);
    } else {
      const call = github.rest.issues.updateLabel({ owner, repo, name: present, new_name: name });
      if (await settle(call, core, `label ${present}`)) {
        core.info(`renamed label ${present} to ${name}`);
      }
    }
  }
}

/**
 * @param {{ github: any, context: import("@actions/github").context, core: any }} params
 */
module.exports = async ({ github, context, core }) => {
  const token = process.env.PROJECT_TOKEN;
  if (!token) {
    throw new Error("PROJECT_TOKEN reaches the boards; it is unset");
  }
  const { owner, repo } = context.repo;

  // Allowed order breaks ties between boards.
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  const topics = new Set(Object.keys(config.topics));
  const labelOf = new Map(Object.entries(config.topics));
  const bucketOf = new Map(Object.entries(config.topics).map(([bucket, label]) => [label, bucket]));
  const boards = [];
  for (const entry of config.projects.allow) {
    const project = { ...config.projects.defaults, ...entry };
    boards.push(await readBoard(token, project, topics, `${owner}/${repo}`, core));
  }

  await mintLabels(github, owner, repo, [...labelOf.values()], core);

  // Apply board buckets to labels for all pull requests, open or not.
  const settled = new Map();
  for (const { where, items } of boards) {
    for (const [number, { bucket, labels }] of items) {
      if (!topics.has(bucket)) {
        continue;
      }
      const prior = settled.get(number);
      if (prior !== undefined) {
        if (prior !== bucket) {
          core.warning(`PR #${number}: ${where} buckets ${bucket}, an earlier board ${prior}`);
        }
        continue;
      }
      settled.set(number, bucket);
      const label = labelOf.get(bucket);
      if (!labels.includes(label)) {
        const call = github.rest.issues.addLabels({ owner, repo, issue_number: number, labels: [label] });
        if (await settle(call, core, `PR #${number}`)) {
          core.info(`PR #${number}: labelled ${label}`);
        }
      }
      for (const name of labels) {
        if (name !== label && bucketOf.has(name)) {
          const call = github.rest.issues.removeLabel({ owner, repo, issue_number: number, name });
          if (await settle(call, core, `PR #${number} label ${name}`)) {
            core.info(`PR #${number}: pruned ${name}`);
          }
        }
      }
    }
  }

  // Bucket unbucketed board items from their label. Never add items to a board.
  for (const pr of await listOpenPulls({ github, owner, repo })) {
    const unbucketed = boards.filter((b) => b.items.get(pr.number)?.bucket === null);
    if (unbucketed.length === 0) {
      continue;
    }
    const held = pr.labels.map((l) => l.name).filter((n) => bucketOf.has(n));
    const topic = settled.get(pr.number) ?? (held.length === 1 ? bucketOf.get(held[0]) : undefined);
    if (topic === undefined) {
      core.warning(`PR #${pr.number} is unbucketed and names ${held.length} topics`);
      continue;
    }
    for (const { where, id, fieldId, options, items } of unbucketed) {
      const item = items.get(pr.number).itemId;
      await graphql(token, SET_TOPIC, { project: id, item, field: fieldId, option: options.get(topic) });
      core.info(`PR #${pr.number}: bucketed ${topic} on ${where}`);
    }
  }
};
