# node:24 target image (bare node:http app, no framework, no runtime deps).
# Pinned to node 24.11.1: the newest 24.x minor where the ESM-loader gadget
# this task teaches still fires. The 24.12.0 loader ignores a polluted
# `Object.prototype.source` for data: URL imports (probed 24.10/24.11 fire,
# 24.12/24.13/24.15/24.21 do not), so do not bump minors silently.
# node:24.11.1 digest pinned: sha256:9a2ed90cd91b1f3412affe080b62e69b057ba8661d9844e143a6bbd76a23260f
FROM node:24.11.1@sha256:9a2ed90cd91b1f3412affe080b62e69b057ba8661d9844e143a6bbd76a23260f

WORKDIR /app
COPY --chown=node:node server.mjs trigger.mjs package.json entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh \
 && touch /flag && chown node:node /flag && chmod 600 /flag

# Run as the image's non-root `node` user.
USER node
ENV FLAG_PATH=/flag
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
