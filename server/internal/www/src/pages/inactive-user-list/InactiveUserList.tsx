import { gql, useQuery, useMutation } from "@apollo/client";
import { User } from '../../types';
import { Table, Button, Loader, Text, Title, Notification } from '@mantine/core';
import { useState } from 'react';

const GET_USERS = gql`
  query GetUsers {
    users {
      id
      name
      isactivated
    }
  }
`;

const ACTIVATE_USER = gql`
  mutation ActivateUser($id: ID!) {
    updateUser(id: $id, input: { isactivated: true }) {
      id
      isactivated
    }
  }
`;

export const InactiveUserList = () => {
  const { loading, error, data, refetch } = useQuery(GET_USERS);
  const [activateUser] = useMutation(ACTIVATE_USER);
  const [notification, setNotification] = useState<{ message: string; color: 'red' | 'green' } | null>(null);


  const handleActivate = async (id: string) => {
    setNotification(null);
    try {
      await activateUser({ variables: { id } });
      setNotification({ message: 'User activated successfully!', color: 'green' });
      refetch();
    } catch (err) {
      console.error("Failed to activate user:", err);
      setNotification({ message: 'Failed to activate user.', color: 'red' });
    }
  };

  if (loading) return <Loader />;
  if (error) return <Text color="red">Error: Could not fetch users.</Text>;

  const inactiveUsers = data?.users?.filter((user: User) => !user.isactivated) || [];

  const rows = inactiveUsers.map((user: User) => (
    <Table.Tr key={user.id}>
      <Table.Td>{user.name}</Table.Td>
      <Table.Td>
        <Button onClick={() => handleActivate(user.id)}>
          Activate
        </Button>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <div style={{ padding: '20px' }}>
      <Title order={2} style={{ marginBottom: '20px' }}>Inactive Users</Title>
      {notification && (
        <Notification
          color={notification.color}
          onClose={() => setNotification(null)}
          title={notification.color === 'green' ? 'Success' : 'Error'}
          style={{ marginBottom: '20px' }}
        >
          {notification.message}
        </Notification>
      )}
      {inactiveUsers.length > 0 ? (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Action</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>{rows}</Table.Tbody>
        </Table>
      ) : (
        <Text>No inactive users found.</Text>
      )}
    </div>
  );
};
