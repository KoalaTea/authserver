import { gql, useQuery } from "@apollo/client";
import { Badge, Button, Group, Table, Title } from "@mantine/core";
import { Link } from "react-router";

const GET_USERS = gql`
    query GetUsers {
        users {
            edges {
                node {
                    id
                    name
                    isactivated
                }
            }
        }
    }
`

export const UserList = () => {
    const { data, loading } = useQuery(GET_USERS);

    const rows = data?.users?.edges?.map((edge: any) => {
        const user = edge.node;
        return (
            <Table.Tr key={user.id}>
                <Table.Td>{user.name}</Table.Td>
                <Table.Td>
                    {user.isactivated ? (
                        <Badge color="green">Active</Badge>
                    ) : (
                        <Badge color="red">Inactive</Badge>
                    )}
                </Table.Td>
                <Table.Td>
                    <Button component={Link} to={`/users/${user.id}`} variant="light" size="xs">
                        Details
                    </Button>
                </Table.Td>
            </Table.Tr>
        );
    });

    return (
        <>
            <Group justify="space-between" mb="md">
                <Title order={2}>Users</Title>
            </Group>

            <Table striped highlightOnHover>
                <Table.Thead>
                    <Table.Tr>
                        <Table.Th>Name</Table.Th>
                        <Table.Th>Status</Table.Th>
                        <Table.Th>Actions</Table.Th>
                    </Table.Tr>
                </Table.Thead>
                <Table.Tbody>{rows}</Table.Tbody>
                {loading && <Table.Caption>Loading users...</Table.Caption>}
            </Table>
        </>
    );
}
