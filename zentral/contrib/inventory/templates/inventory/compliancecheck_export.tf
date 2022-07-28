{% load base_extras %}
{% autoescape off %}
{% for tag in tags %}
data "zentral_tag" "tag{{ tag.pk }}" {
  name = {{ tag.name|tf_quoted_str }}
}

{% endfor %}{% for cc in compliance_checks %}
resource "zentral_jmespath_check" "check{{ cc.pk }}" {
  name                = {{ cc.compliance_check.name|tf_quoted_str }}
  description         = {{ cc.compliance_check.description|tf_quoted_str }}
  source_name         = {{ cc.source_name|tf_quoted_str }}
  platforms           = [{% for pf in cc.platforms %}{{ pf|tf_quoted_str }}{% if not forloop.last %}, {% endif %}{% endfor %}]
  tag_ids             = [{% for tag in cc.tags.all %}data.zentral_tag.tag{{ tag.pk }}.id{% if not forloop.last %}, {% endif %}{% endfor %}]
  jmespath_expression = {{ cc.jmespath_expression|tf_quoted_str }}
}

{% endfor %}
{% endautoescape %}
