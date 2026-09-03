# Zentral documentation

The pages in `content/` are the source of https://www.zentral.com/docs/. The
website build clones this repository, mounts `content/` and `layouts/` into its
own Hugo site, and publishes the result. This directory is also a complete Hugo
site on its own, which is what the preview below serves.

## Preview

```
docker compose -f docker-compose.docs.yml up
```

Then open http://localhost:1314. The pages reload as you save.

To run the same check the CI does:

```
docker compose -f docker-compose.docs.yml run --rm docs hugo --panicOnWarning
```

## Writing

- One page per file. `title` and `weight` in the front matter set the label and
  the position in the sidebar.
- Link to another page by its path, with the `.md` extension:
  `[the API section](../configuration/api.md)`. A build failure means the target
  does not exist — the link is resolved against the page tree, not left for the
  browser to guess.
- Images live in `content/images/` and are addressed relative to the page.
- Raw HTML is dropped. This repository takes public pull requests and the output
  is served from the company website, so markdown has to be enough.

The Hugo version and the markup options are pinned in two places, here and in
the website repository. `hugo.yaml` and `conf/start/docker/hugo/Dockerfile` say
what has to stay in step.
