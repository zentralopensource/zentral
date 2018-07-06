from .api_client import APIClient, APIClientError


def build_and_upload_app(api_key, builder, enrollment):
    # build package
    b = builder(enrollment)
    package_filename, _, package_content = b.build()
    # upload package
    api_client = APIClient(api_key)
    try:
        response = api_client.upload_app(package_filename, package_content)
    except APIClientError as api_error:
        # upload error
        err_msg = ". ".join(s for s in ("Could not upload app to simplemdm", api_error.message) if s)
        return None, None, err_msg
    else:
        return response["attributes"]["name"], response["id"], ""


def delete_app(api_key, app_simplemdm_id):
    api_client = APIClient(api_key)
    try:
        if api_client.delete_app(app_simplemdm_id):
            success_message = "App removed from SimpleMDM"
        else:
            success_message = None
        return success_message, None
    except APIClientError:
        return None, "SimpleMDM API Error. Could not delete app."
