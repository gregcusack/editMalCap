from statistics import stdev, mean
import numpy as np
from scipy.stats import truncnorm

x = [0,2,4,5,10,13,20]
for i in range(len(x)):
	#i += 1
	print(i)


# def get_truncnorm(mean=0, sd=1, low=0, upp=10):
#     return truncnorm((low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)

# GOAL_IA = 15

# mu = .008624
# sigma = .04287
# x = [0,2,4,5,10,13,20]
# s = np.random.normal(mu, sigma, 149)

# X = get_truncnorm(mu, sigma, 0, x[len(x)-1]- x[0])
# X = X.rvs(80)
# print(X)

# print(X[0])


# def meanIA(l):
# 	total = l[len(l)-1] - l[0]
# 	return total / (len(l) - 1)

# def diffArr(inA, outA):
# 	prev = inA[0]
# 	i = 1
# 	for i in range(len(inA)):
# 		outA.append(inA[i] - prev)
# 		prev = inA[i]
# 		i += 1
# 	outA.pop(0)

# x = [0,2,4,5,10,13,20]
# xDiff = []
# yDiff = []
# zDiff = []
# diffArr(x, xDiff)

# print(x)
# print(xDiff)
# print(meanIA(x))
# print(stdev(xDiff))
# print("-----")

# prevts = x[0]
# y = []
# y.append(x[0])
# for i in x:
# 	i = prevts + GOAL_IA
# 	prevts = i
# 	y.append(i)

# diffArr(y, yDiff)

# print(y)
# print(yDiff)
# print(meanIA(y))
# print(stdev(yDiff))
# print("-----")

# z = [0, 26, 30, 45, 60, 75, 90, 105]
# diffArr(z, zDiff)
# print(z)
# print(zDiff)
# print(meanIA(z))
# print(stdev(zDiff))
