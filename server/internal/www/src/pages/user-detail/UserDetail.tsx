import { gql, useMutation, useQuery } from "@apollo/client";
import { Button, Card, Group, Stack, Switch, Text, Title } from "@mantine/core";
import { useParams, Link } from "react-router";

const GET_USER = gql`
  query GetUser($id: ID!) {
    node(id: $id) {
      ... on User {
        id
        name
        isactivated
      }
    }
  }
`;

const UPDATE_USER = gql`
  mutation UpdateUser($id: ID!, $input: UpdateUserInput!) {
    updateUser(id: $id, input: $input) {
      id
      isactivated
    }
  }
`;

export const UserDetail = () => {
  const { id } = useParams();
  const { data, loading, error } = useQuery(GET_USER, {
    variables: { id },
  });

  const [updateUser, { loading: updating }] = useMutation(UPDATE_USER);

  if (loading) return <Text>Loading user...</Text>;
  if (error) return <Text color="red">Error loading user: {error.message}</Text>;

  const user = data?.node;

  if (!user) return <Text>User not found</Text>;

  const handleToggleActive = async () => {
    try {
      await updateUser({
        variables: {
          id: user.id,
          input: {
            isactivated: !user.isactivated,
          },
        },
      });
    } catch (e) {
      console.error("Failed to update user", e);
    }
  };

  return (
    <Stack>
      <Group>
        <Button component={Link} to="/users" variant="subtle">
          Back to Users
        </Button>
      </Group>

      <Title order={2}>User Details: {user.name}</Title>

      <Card shadow="sm" padding="lg" radius="md" withBorder>
        <Stack>
          <Group justify="space-between">
            <Text fw={500}>User ID</Text>
            <Text>{user.id}</Text>
          </Group>

          <Group justify="space-between">
            <Text fw={500}>Name</Text>
            <Text>{user.name}</Text>
          </Group>

          <Group justify="space-between">
            <Text fw={500}>Status</Text>
            <Switch
              label={user.isactivated ? "Active" : "Inactive"}
              checked={user.isactivated}
              onChange={handleToggleActive}
              disabled={updating}
            />
          </Group>
        </Stack>
      </Card>
    </Stack>
  );
};
