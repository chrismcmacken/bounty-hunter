# Test cases for python-unsafe-yaml-load rules
import yaml

def test_no_loader():
    data = get_user_input()

    # ruleid: python-yaml-load-no-loader
    obj = yaml.load(data)

    # ruleid: python-yaml-load-no-loader
    for doc in yaml.load_all(data):
        process(doc)


def test_unsafe_loaders():
    data = get_user_input()

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.Loader)

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.UnsafeLoader)

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.FullLoader)

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.CLoader)

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load_all(data, Loader=yaml.Loader)

    # ruleid: python-yaml-load-unsafe-loader
    yaml.load_all(data, Loader=yaml.UnsafeLoader)


def test_unsafe_load_function():
    data = get_user_input()

    # ruleid: python-yaml-unsafe-load-function
    yaml.unsafe_load(data)

    # ruleid: python-yaml-unsafe-load-function
    yaml.unsafe_load_all(data)


def test_safe_patterns():
    data = get_user_input()

    # ok: python-yaml-load-no-loader
    # ok: python-yaml-load-unsafe-loader
    yaml.safe_load(data)

    # ok: python-yaml-load-no-loader
    # ok: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.SafeLoader)

    # ok: python-yaml-load-no-loader
    # ok: python-yaml-load-unsafe-loader
    yaml.load(data, Loader=yaml.CSafeLoader)

    # ok: python-yaml-load-no-loader
    # ok: python-yaml-load-unsafe-loader
    yaml.safe_load_all(data)

    # ok: python-yaml-load-no-loader
    # ok: python-yaml-load-unsafe-loader
    yaml.load_all(data, Loader=yaml.SafeLoader)
