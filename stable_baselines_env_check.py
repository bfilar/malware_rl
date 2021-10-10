import gym
from stable_baselines3.common.env_checker import check_env

import malware_rl  # Needs to be included in order to make the environment using gym


def test_env(env_name):

    print(f"TESTING {env_name}!")
    env = gym.make(env_name)
    print("Checking environment . . .")
    check_env(env)
    env.close()


environments = ["sorel-train-v0", "malconv-train-v0", "ember-train-v0"]

for e in environments:
    test_env(e)
