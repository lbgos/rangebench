#!/bin/bash
# one command per connection, executed as the connecting user (dev)
read -r line
eval "$line"
