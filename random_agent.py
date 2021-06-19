import os
import random
import sys

import gym
import numpy as np
from gym import wrappers
from IPython import embed

import malware_rl

random.seed(0)
module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]


class RandomAgent:
    """The world's simplest agent!"""

    def __init__(self, action_space):
        self.action_space = action_space

    def act(self, observation, reward, done):
        return self.action_space.sample()


# gym setup
outdir = os.path.join(module_path, "data/logs/random-agent-results")
env = gym.make("malconv-train-v0")
env = wrappers.Monitor(env, directory=outdir, force=True)
env.seed(0)
episode_count = 250
done = False
reward = 0

# metric tracking
evasions = 0
evasion_history = {}

agent = RandomAgent(env.action_space)

for i in range(episode_count):
    ob = env.reset()
    sha256 = env.env.sha256
    while True:
        action = agent.act(ob, reward, done)
        ob, reward, done, ep_history = env.step(action)
        if done and reward >= 10.0:
            evasions += 1
            evasion_history[sha256] = ep_history
            break

        elif done:
            break

evasion_rate = (evasions / episode_count) * 100
mean_action_count = np.mean(env.get_episode_lengths())
print(f"{evasion_rate}% samples evaded model.")
print(f"Average of {mean_action_count} moves to evade model.")
embed()
