"""Tabular Q-learning on a chain: train, checkpoint, resume, and check the resumed run equals a straight run."""

import argparse
import json
from pathlib import Path

import numpy as np

STATES, ACTIONS, GOAL, EPISODES = 8, 2, 7, 200


def step(state, action):
    nxt = min(state + 1, GOAL) if action == 1 else max(state - 1, 0)
    return nxt, float(nxt == GOAL)


def train(q, rng, episodes, alpha=0.5, gamma=0.9, epsilon=0.2):
    returns = []
    for _ in range(episodes):
        state, total = 0, 0.0
        for _ in range(50):
            explore = rng.random() < epsilon
            action = int(rng.integers(ACTIONS)) if explore else int(np.argmax(q[state]))
            nxt, reward = step(state, action)
            q[state, action] += alpha * (reward + gamma * q[nxt].max() * (nxt != GOAL) - q[state, action])
            state, total = nxt, total + reward
            if state == GOAL:
                break
        returns.append(total)
    return returns


def save(folder, q, rng):
    np.save(folder / "q.npy", q)
    (folder / "rng.json").write_text(json.dumps(rng.bit_generator.state))


def load(folder):
    rng = np.random.default_rng()
    rng.bit_generator.state = json.loads((folder / "rng.json").read_text())
    return np.load(folder / "q.npy"), rng


def greedy_steps(q):
    state, steps = 0, 0
    while state != GOAL and steps < 50:
        state, _ = step(state, int(np.argmax(q[state])))
        steps += 1
    return steps


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    out = Path(parser.parse_args().out)
    folder = out.parent / "checkpoint"
    folder.mkdir(exist_ok=True)
    straight_q = np.ones((STATES, ACTIONS))  # optimistic start: unvisited moves look best, so it explores
    straight = train(straight_q, np.random.default_rng(7), EPISODES)
    q, rng = np.ones((STATES, ACTIONS)), np.random.default_rng(7)
    first = train(q, rng, EPISODES // 2)
    save(folder, q, rng)
    q, rng = load(folder)
    resumed = first + train(q, rng, EPISODES - EPISODES // 2)
    out.write_text(
        json.dumps(
            {
                "episodes": EPISODES,
                "greedy_steps_to_goal": greedy_steps(q),
                "max_abs_q_difference": float(np.abs(q - straight_q).max()),
                "reproduced": int(resumed == straight and np.array_equal(q, straight_q)),
                "returns_last_20": resumed[-20:],
            }
        )
    )


if __name__ == "__main__":
    main()
