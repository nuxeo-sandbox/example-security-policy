# Example Security Policy

Example security policy package for the Nuxeo Repository.

## Use Case

The example security policy uses a metadata field to control access to the underlying document.  In this example, we expect the "dc:description" / Description field to be either blank (normal security rules apply) or the value `RestrictedView` (the security policy applies).  When set to `RestrictedView`, the User must be in either group "GroupOne" or "GroupTwo" in order to see the document.  If they are not, the document is forbidden from view.

Caution: When the description is set to a value other than `RestrictedView`, no one will be able to see the document for this particular example.  In a production use case, you would use a field other than `dc:description` and would most likely have a drop-down select field for the possible values of the `ACCOUNT_TYPE` metadata field defined in `ExamplePolicy.java`.

## Support

**These features are sand-boxed and not yet part of the Nuxeo Production platform.**

These solutions are provided for inspiration and we encourage customers to use them as code samples and learning resources.

This is a moving project (no API maintenance, no deprecation process, etc.) If any of these solutions are found to be useful for the Nuxeo Platform in general, they will be integrated directly into platform, not maintained here.

## Licensing

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## About Nuxeo

Nuxeo dramatically improves how content-based applications are built, managed and deployed, making customers more agile, innovative and successful. Nuxeo provides a next generation, enterprise ready platform for building traditional and cutting-edge content oriented applications. Combining a powerful application development environment with SaaS-based tools and a modular architecture, the Nuxeo Platform and Products provide clear business value to some of the most recognizable brands including Verizon, Electronic Arts, Sharp, FICO, the U.S. Navy, and Boeing. Nuxeo is headquartered in New York and Paris.

More information is available at [www.nuxeo.com](http://www.nuxeo.com).

