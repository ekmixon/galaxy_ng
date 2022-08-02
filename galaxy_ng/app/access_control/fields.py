from django.contrib.auth.models import Permission
from django.db.models import Q

from guardian.shortcuts import get_perms_for_model

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from galaxy_ng.app.models import auth as auth_models


class GroupPermissionField(serializers.Field):
    def _validate_group(self, group_data):
        if 'object_permissions' not in group_data:
            raise ValidationError(detail={
                'groups': 'object_permissions field is required'})

        if 'id' not in group_data and 'name' not in group_data:
            raise ValidationError(detail={
                'groups': 'id or name field is required'})

        perms = group_data['object_permissions']

        if not isinstance(perms, list):
            raise ValidationError(detail={
                'groups': 'object_permissions must be a list of strings'})

        # validate that the permissions exist
        for perm in perms:
            if '.' in perm:
                app_label, codename = perm.split('.', maxsplit=1)
                filter_q = Q(content_type__app_label=app_label) & Q(codename=codename)
            else:
                filter_q = Q(codename=perm)

            # TODO(newswangerd): Figure out how to make this one SQL query instead of
            # performing N queries for each permission
            if not Permission.objects.filter(filter_q).exists():
                raise ValidationError(detail={'groups': f'Permission {perm} does not exist'})

    def to_representation(self, value):
        return [
            {
                'id': group.id,
                'name': group.name,
                'object_permissions': value[group],
            }
            for group in value
        ]

    def to_internal_value(self, data):
        if not isinstance(data, list):
            raise ValidationError(detail={
                'groups': 'Groups must be a list of group objects'
            })

        internal = {}
        for group_data in data:
            self._validate_group(group_data)
            group_filter = {
                field: group_data[field]
                for field in group_data
                if field in ('id', 'name')
            }

            try:
                group = auth_models.Group.objects.get(**group_filter)
                internal[group] = group_data['object_permissions']
            except auth_models.Group.DoesNotExist:
                raise ValidationError(
                    detail={
                        'groups': f"Group name={group_data.get('name')}, id={group_data.get('id')} does not exist"
                    }
                )

            except ValueError:
                raise ValidationError(detail={'group': 'Invalid group name or ID'})

        return internal


class MyPermissionsField(serializers.Serializer):
    def to_representation(self, obj):
        user = self.context['request'].user

        # guardian's get_perms(user, obj) method only returns user permissions,
        # not all permissions a user has.
        my_perms = []
        for perm in get_perms_for_model(type(obj)).all():
            codename = f"{perm.content_type.app_label}.{perm.codename}"
            if user.has_perm(codename) or user.has_perm(codename, obj):
                my_perms.append(codename)

        return my_perms
