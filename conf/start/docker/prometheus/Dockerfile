FROM    prom/prometheus
ADD     prometheus.yml /etc/prometheus/
CMD     [ "--config.file=/etc/prometheus/prometheus.yml", \
          "--storage.tsdb.path=/prometheus", \
          "--web.console.libraries=/etc/prometheus/console_libraries", \
          "--web.console.templates=/etc/prometheus/consoles", \
          "--web.external-url=https://zentral/prometheus/" ]
