from django.urls import path
from . import views

app_name = "santa"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name="index"),

    # configuration / enrollment
    path('configurations/',
         views.ConfigurationListView.as_view(),
         name='configuration_list'),
    path('configurations/create/',
         views.CreateConfigurationView.as_view(),
         name='create_configuration'),
    path('configurations/<int:pk>/',
         views.ConfigurationView.as_view(),
         name='configuration'),
    path('configurations/<int:pk>/events/',
         views.ConfigurationEventsView.as_view(),
         name='configuration_events'),
    path('configurations/<int:pk>/events/fetch/',
         views.FetchConfigurationEventsView.as_view(),
         name='fetch_configuration_events'),
    path('configurations/<int:pk>/events/store_redirect/',
         views.ConfigurationEventsStoreRedirectView.as_view(),
         name='configuration_events_store_redirect'),
    path('configurations/<int:pk>/update/',
         views.UpdateConfigurationView.as_view(),
         name='update_configuration'),
    path('configurations/<int:pk>/delete/',
         views.DeleteConfigurationView.as_view(),
         name='delete_configuration'),
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(),
         name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/delete/',
         views.DeleteEnrollmentView.as_view(),
         name='delete_enrollment'),
    path('configurations/<int:configuration_pk>/target_states/<int:pk>/reset/',
         views.ResetTargetStateView.as_view(),
         name='reset_target_state'),

    # voting groups
    path('configurations/<int:configuration_pk>/voting_groups/create/',
         views.CreateVotingGroupView.as_view(),
         name='create_voting_group'),
    path('configurations/<int:configuration_pk>/voting_groups/<int:pk>/update/',
         views.UpdateVotingGroupView.as_view(),
         name='update_voting_group'),
    path('configurations/<int:configuration_pk>/voting_groups/<int:pk>/delete/',
         views.DeleteVotingGroupView.as_view(),
         name='delete_voting_group'),

    # rules
    path('configurations/<int:configuration_pk>/rules/',
         views.ConfigurationRulesView.as_view(),
         name='configuration_rules'),
    path('configurations/<int:configuration_pk>/rules/create/',
         views.CreateConfigurationRuleView.as_view(),
         name='create_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/<int:pk>/update/',
         views.UpdateConfigurationRuleView.as_view(),
         name='update_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/<int:pk>/delete/',
         views.DeleteConfigurationRuleView.as_view(),
         name='delete_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/pick_binary/',
         views.PickRuleBinaryView.as_view(),
         name='pick_rule_binary'),
    path('configurations/<int:configuration_pk>/rules/pick_certificate/',
         views.PickRuleCertificateView.as_view(),
         name='pick_rule_certificate'),
    path('configurations/<int:configuration_pk>/rules/pick_team_id/',
         views.PickRuleTeamIDView.as_view(),
         name='pick_rule_team_id'),
    path('configurations/<int:configuration_pk>/rules/pick_cdhash/',
         views.PickRuleCDHashView.as_view(),
         name='pick_rule_cdhash'),
    path('configurations/<int:configuration_pk>/rules/pick_signing_id/',
         views.PickRuleSigningIDView.as_view(),
         name='pick_rule_signing_id'),

    # targets
    path('targets/', views.TargetsView.as_view(), name="targets"),
    # binary
    path('targets/binary/<str:identifier>/', views.BinaryView.as_view(), name="binary"),
    path('targets/binary/<str:identifier>/events/',
         views.BinaryEventsView.as_view(), name="binary_events"),
    path('targets/binary/<str:identifier>/events/fetch/',
         views.FetchBinaryEventsView.as_view(), name="fetch_binary_events"),
    path('targets/binary/<str:identifier>/events/store_redirect/',
         views.BinaryEventsStoreRedirectView.as_view(), name="binary_events_store_redirect"),
    # bundle
    path('targets/bundle/<str:identifier>/', views.BundleView.as_view(), name="bundle"),
    # metabundle
    path('targets/metabundle/<str:identifier>/', views.MetaBundleView.as_view(), name="metabundle"),
    # certificate
    path('targets/certificate/<str:identifier>/', views.CertificateView.as_view(), name="certificate"),
    path('targets/certificate/<str:identifier>/events/',
         views.CertificateEventsView.as_view(), name="certificate_events"),
    path('targets/certificate/<str:identifier>/events/fetch/',
         views.FetchCertificateEventsView.as_view(), name="fetch_certificate_events"),
    path('targets/certificate/<str:identifier>/events/store_redirect/',
         views.CertificateEventsStoreRedirectView.as_view(), name="certificate_events_store_redirect"),
    # team id
    path('targets/teamid/<str:identifier>/', views.TeamIDView.as_view(), name="teamid"),
    path('targets/teamid/<str:identifier>/events/',
         views.TeamIDEventsView.as_view(), name="teamid_events"),
    path('targets/teamid/<str:identifier>/events/fetch/',
         views.FetchTeamIDEventsView.as_view(), name="fetch_teamid_events"),
    path('targets/teamid/<str:identifier>/events/store_redirect/',
         views.TeamIDEventsStoreRedirectView.as_view(), name="teamid_events_store_redirect"),
    # cdhash
    path('targets/cdhash/<str:identifier>/', views.CDHashView.as_view(), name="cdhash"),
    path('targets/cdhash/<str:identifier>/events/',
         views.CDHashEventsView.as_view(), name="cdhash_events"),
    path('targets/cdhash/<str:identifier>/events/fetch/',
         views.FetchCDHashEventsView.as_view(), name="fetch_cdhash_events"),
    path('targets/cdhash/<str:identifier>/events/store_redirect/',
         views.CDHashEventsStoreRedirectView.as_view(), name="cdhash_events_store_redirect"),
    # signing id
    path('targets/signingid/<str:identifier>/', views.SigningIDView.as_view(), name="signingid"),
    path('targets/signingid/<str:identifier>/events/',
         views.SigningIDEventsView.as_view(), name="signingid_events"),
    path('targets/signingid/<str:identifier>/events/fetch/',
         views.FetchSigningIDEventsView.as_view(), name="fetch_signingid_events"),
    path('targets/signingid/<str:identifier>/events/store_redirect/',
         views.SigningIDEventsStoreRedirectView.as_view(), name="signingid_events_store_redirect"),

    # ballots
    path('ballots/', views.BallotsView.as_view(), name="ballots"),
    path('ballots/cast/', views.CastBallotView.as_view(), name="cast_ballot"),

    # terraform
    path('terraform_export/',
         views.TerraformExportView.as_view(),
         name='terraform_export'),
]


modules_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('santa',)),
        ('configuration_list', 'Configurations', False, ('santa.view_configuration',)),
        ('targets', 'Targets', False, ('santa.view_target',)),
        ('ballots', 'Ballots', False, ('santa.view_ballot',)),
    ),
    'weight': 50,
}
