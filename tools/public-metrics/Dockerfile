FROM node:24-bookworm-slim
WORKDIR /app
COPY --chown=node:node *.mjs ./
RUN mkdir /data && chown node:node /data
USER node
ENV AMA_METRICS_HOST=0.0.0.0 AMA_METRICS_PORT=8788 AMA_METRICS_DB=/data/activity.sqlite
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD node -e "fetch('http://127.0.0.1:8788/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node","daemon.mjs"]
